/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * gnome-clang
 * Copyright © 2014 Philip Withnall
 *
 * gnome-clang is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gnome-clang is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gnome-clang.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Philip Withnall <philip@tecnocode.co.uk>
 */

/**
 * GVariantVisitor:
 *
 * This is a checker for GVariant format strings and varargs. For GVariant
 * methods which accept varargs, it validates the type and nullability of each
 * vararg against the corresponding element in the GVariant format string (if
 * a constant format string is provided — non-constant format strings cannot be
 * validated, but the user should probably be using GVariantBuilder directly if
 * they’re dynamically generating a format string).
 *
 * For GVariant methods with format strings but no varargs, the format string is
 * validated.
 *
 * The format string is parsed and varargs are consumed in parallel. The static
 * type of the varargs is used, so if a weird cast is used (e.g. casting a
 * string literal to an integer and passing it to a ‘u’ format string), no error
 * will be raised. One limitation on the current checker is that the types of
 * GVariants passed in are not checked. e.g. No error is emitted for the
 * following invalid code:
 *     g_variant_new ('@s', g_variant_new_boolean (FALSE));
 *
 * The error messages produced by this checker should give as much context and
 * guidance towards fixing the problem as possible. Empirically, it seems that
 * the GVariant Format String documentation in GLib’s manual is used quite a
 * lot, since people can’t memorise the format strings. Contextual help in the
 * error messages should try to avoid this.
 *
 * FIXME: Future work could be to implement:
 *  • Reference counting validation of GVariants (might be better placed in a
 *    general reference counting checker).
 *  • GVariant print format parsing (for g_variant_new_parsed()).
 *  • Character-granularity error diagnostic locations, e.g. pointing to the
 *    erroneous character in a format string, not just to the start of the
 *    format string argument itself.
 *
 * FIXME: If Clang’s DiagnosticsEngine gains support for multiple
 * SourceLocations, it would be great to highlight both the relevant character
 * of the GVariant format string, and the erroneous variadic arguments in the
 * function call, when an error is printed. At the moment we have to just pick
 * the most important of the two and highlight that.
 */

#include <cstring>

#include <clang/AST/Attr.h>

#include <glib.h>

#include "debug.h"
#include "gvariant-checker.h"


/* Information about the GVariant functions we’re interested in. If you want to
 * add support for a new GVariant function, it may be enough to add a new
 * element here. */
typedef struct {
	/* C name of the function */
	const char *func_name;
	/* Zero-based index of the GVariant format string parameter to the
	 * function; the validity of this string will be checked */
	unsigned int format_param_index;
	/* Zero-based index of the first varargs parameter or va_list. */
	unsigned int first_vararg_param_index;
	/* Whether the function takes a va_list instead of varargs. */
	bool uses_va_list;
} VariantFuncInfo;

static const VariantFuncInfo gvariant_format_funcs[] = {
	{ "g_variant_new", 0, 1, false },
	{ "g_variant_new_va", 0, 2, true },
/* TODO:
	{ "g_variant_get", 1, 2, false },
	{ "g_variant_get_va", 1, 3, true },
	{ "g_variant_get_child", 2, 3, false },
	{ "g_variant_lookup", 2, 3, false },
	{ "g_variant_iter_next", 1, 2, false },
	{ "g_variant_iter_loop", 1, 2, false },
	{ "g_variant_builder_add", 1, 2, false },
	{ "g_variant_builder_add_parsed", 1, 2, false },
*/
};

static const VariantFuncInfo *
_func_uses_gvariant_format (const FunctionDecl& func)
{
	const char *func_name = func.getNameAsString ().c_str ();
	guint i;

	/* Fast path elimination of irrelevant functions. */
	if (*func_name != 'g')
		return NULL;

	for (i = 0; i < G_N_ELEMENTS (gvariant_format_funcs); i++) {
		if (strcmp (func_name, gvariant_format_funcs[i].func_name) == 0)
			return &gvariant_format_funcs[i];
	}

	return NULL;
}

/* Consume a single variadic argument from the varargs array, checking that one
 * exists and has the given @expected_type. If @force_gvariant_pointer is set,
 * the expected type is forced to be GVariant*. (This is necessary because I can
 * find no way to represent GVariant* as a QualType. If someone can fix that,
 * the boolean argument can be removed.) Same for
 * @force_gvariantbuilder_pointer, but with GVariantBuilder*.
 *
 * Iff @allow_maybe is true, the variadic argument may be NULL. This will emit
 * errors where found. */
static bool
_consume_variadic_argument (QualType expected_type,
                            CallExpr::const_arg_iterator *args_begin,
                            CallExpr::const_arg_iterator *args_end,
                            bool force_gvariant_pointer,
                            bool force_gvariantbuilder_pointer,
                            bool allow_maybe, CompilerInstance& compiler,
                            const StringLiteral *format_arg_str,
                            ASTContext& context,
                            bool consume_vararg)
{
	DEBUG ("Consuming variadic argument with expected type ‘" <<
	       expected_type.getAsString () << "’.");

	std::string expected_type_str;

	if (force_gvariantbuilder_pointer) {
		/* Note: Stricter checking is implemented below. */
		DEBUG ("Forcing expected type to ‘GVariantBuilder*’.");
		expected_type = context.VoidPtrTy;
		expected_type_str = std::string ("GVariantBuilder *");
	} else if (force_gvariant_pointer) {
		/* Note: Stricter checking is implemented below. */
		DEBUG ("Forcing expected type to ‘GVariant*’.");
		expected_type = context.VoidPtrTy;
		expected_type_str = std::string ("GVariant *");
	} else {
		expected_type_str = expected_type.getAsString ();
	}

	if (*args_begin == *args_end) {
		gchar *error;

		error = g_strdup_printf (
			"Expected a GVariant variadic argument of type ‘%s’ "
			"but there wasn’t one.",
			expected_type_str.c_str ());
		Debug::emit_error (error, compiler,
		                   format_arg_str->getLocStart ());
		g_free (error);

		return false;
	}

	const Expr *arg = **args_begin;

	/* Check its nullability. */
	const QualType& actual_type = arg->getType ();
	bool is_null_constant = arg->isNullPointerConstant (context,
	                                                    Expr::NPC_ValueDependentIsNull);

	if (is_null_constant && !allow_maybe) {
		gchar *error;

		error = g_strdup_printf (
			"Expected a GVariant variadic argument of type ‘%s’ "
			"but saw NULL instead.",
			expected_type_str.c_str ());
		Debug::emit_error (error, compiler,
		                   arg->getLocStart ());
		g_free (error);

		return false;
	} else if (!is_null_constant &&
	           (force_gvariant_pointer || force_gvariantbuilder_pointer)) {
		/* Special case handling for GVariant[Builder]* types, because I
		 * can’t find a reasonable way of retrieving the QualType for
		 * the GVariant or GVariantBuilder typedefs; so we use this
		 * hacky approach instead. */
		const PointerType *actual_pointer_type = dyn_cast<PointerType> (actual_type);
		if (actual_pointer_type == NULL) {
			gchar *error;

			error = g_strdup_printf (
				"Expected a GVariant variadic argument of type "
				"‘%s’ but saw one of type ‘%s’.",
				expected_type_str.c_str (),
				actual_type.getAsString ().c_str ());
			Debug::emit_error (error, compiler,
			                   arg->getLocStart ());
			g_free (error);

			return false;
		}

		QualType actual_pointee_type = actual_pointer_type->getPointeeType ();
		if (!(force_gvariantbuilder_pointer &&
		      actual_pointee_type.getUnqualifiedType ().getAsString () == "GVariantBuilder") &&
		    !(force_gvariant_pointer &&
		      actual_pointee_type.getUnqualifiedType ().getAsString () == "GVariant")) {
			gchar *error;

			error = g_strdup_printf (
				"Expected a GVariant variadic argument of type "
				"‘%s’ but saw one of type ‘%s’.",
				expected_type_str.c_str (),
				actual_type.getAsString ().c_str ());
			Debug::emit_error (error, compiler,
			                   arg->getLocStart ());
			g_free (error);

			return false;
		}
	} else if (!is_null_constant &&
	           !force_gvariant_pointer && !force_gvariantbuilder_pointer) {
		/* Normal non-GVariant case. */
		const PointerType *actual_pointer_type = dyn_cast<PointerType> (actual_type);
		QualType actual_pointee_type;
		if (actual_pointer_type != NULL)
			actual_pointee_type = actual_pointer_type->getPointeeType ();

		const PointerType *expected_pointer_type = dyn_cast<PointerType> (expected_type);
		QualType expected_pointee_type;
		if (expected_pointer_type != NULL)
			expected_pointee_type = expected_pointer_type->getPointeeType ();

		/* Check it’s of @expected_type. We need to compare the
		 * unqualified (with const, volatile, restrict removed) types,
		 * plus the unqualified pointee types if the normal types are
		 * pointers.
		 * .e.g
		 *    char* ≡ const char*
		 *    int ≡ int
		 *    char* ≡char*
		 *    GVariant* ≡ const GVariant* */
		if (!context.hasSameUnqualifiedType (actual_type,
		                                     expected_type) &&
		    (actual_pointer_type == NULL ||
		     expected_pointer_type == NULL ||
		     !context.hasSameUnqualifiedType (actual_pointee_type,
		                                      expected_pointee_type))) {
			gchar *error;

			error = g_strdup_printf (
				"Expected a GVariant variadic argument of type "
				"‘%s’ but saw one of type ‘%s’.",
				expected_type.getAsString ().c_str (),
				actual_type.getAsString ().c_str ());
			Debug::emit_error (error, compiler,
			                   arg->getLocStart ());
			g_free (error);

			return false;
		}
	}

	/* If the GVariant method doesn’t use varargs, don’t actually consume
	 * the argument. */
	if (consume_vararg)
		*args_begin = *args_begin + 1;  /* consume the format */

	return true;
}

/* Parse a single basic type string from the beginning of the string pointed to
 * by @type_str (i.e. *type_str). Consume any variadic parameters from
 * @args_begin as appropriate. This will emit errors where found.
 *
 * @type_str and @args_begin are updated as the type string and arguments are
 * consumed. */
static bool
_check_basic_type_string (const gchar **type_str,
                          CallExpr::const_arg_iterator *args_begin,
                          CallExpr::const_arg_iterator *args_end,
                          bool force_gvariant_pointer,
                          bool force_gvariantbuilder_pointer,
                          bool allow_maybe, CompilerInstance& compiler,
                          const StringLiteral *format_arg_str,
                          ASTContext& context,
                          bool consume_vararg)
{
	DEBUG ("Checking basic type string ‘" << *type_str << "’.");

	QualType expected_type;

	/* Reference: GVariant Type Strings. */
	switch (**type_str) {
	/* Numeric Types */
	case 'b': /* gboolean ≡ gint ≡ int */
		expected_type = context.IntTy;
		break;
	case 'y': /* guchar ≡ unsigned char */
		expected_type = context.UnsignedCharTy;
		break;
	case 'n': /* gint16 */
		expected_type = context.getIntTypeForBitwidth (16, true);
		break;
	case 'q': /* guint16 */
		expected_type = context.getIntTypeForBitwidth (16, false);
		break;
	case 'i':
	case 'h': /* gint32 */
		expected_type = context.getIntTypeForBitwidth (32, true);
		break;
	case 'u': /* guint32 */
		expected_type = context.getIntTypeForBitwidth (32, false);
		break;
	case 'x': /* gint64 */
		expected_type = context.getIntTypeForBitwidth (64, true);
		break;
	case 't': /* guint64 */
		expected_type = context.getIntTypeForBitwidth (64, false);
		break;
	case 'd': /* gdouble ≡ double */
		expected_type = context.DoubleTy;
		break;
	/* Strings */
	case 's':
	case 'o':
	case 'g': /* gchar* ≡ char* */
		/* FIXME: Could also validate o and g as D-Bus object paths and
		 * type signatures. */
		expected_type = context.getPointerType (context.CharTy);
		break;
	/* Basic types */
	case '?': /* GVariant* of any type */
		/* Stricter validation is applied in
		 * _consume_variadic_argument(). */
		expected_type = context.VoidPtrTy;
		force_gvariant_pointer = true;
		break;
	default:
		gchar *error;

		error = g_strdup_printf ("Expected a GVariant basic type "
		                         "string but saw ‘%c’.", **type_str);
		Debug::emit_error (error, compiler,
		                   format_arg_str->getLocStart ());
		g_free (error);

		return false;
	}

	/* Handle type promotion. Integer types which are smaller than 32 bits
	 * (for all architectures we care about) are automatically promoted to
	 * 32 bits when passed as varargs.
	 *
	 * A subtlety of the standard (ISO/IEC 9899, §6.3.1.1¶2) means that all
	 * types are promoted to *signed* 32-bit integers. This is because int
	 * can represent all values representable by 16-bit (and smaller)
	 * unsigned integers.
	 *
	 * References:
	 *  • GVariant Format Strings, §Numeric Types
	 *  • ISO/IEC 9899, §6.5.2.2¶6
	 */
	if (**type_str == 'y' || **type_str == 'n' || **type_str == 'q') {
		assert (expected_type->isPromotableIntegerType ());
		expected_type = context.IntTy;
	}

	/* Consume the type string. */
	*type_str = *type_str + 1;

	return _consume_variadic_argument (expected_type,
	                                   args_begin, args_end,
	                                   force_gvariant_pointer,
	                                   force_gvariantbuilder_pointer,
	                                   allow_maybe, compiler,
	                                   format_arg_str, context,
	                                   consume_vararg);
}

/* Parse a single type string from the beginning of the string pointed to
 * by @type_str (i.e. *type_str). Consume any variadic parameters from
 * @args_begin as appropriate. This will emit errors where found.
 *
 * @type_str and @args_begin are updated as the type string and arguments are
 * consumed. */
static bool
_check_type_string (const gchar **type_str,
                    CallExpr::const_arg_iterator *args_begin,
                    CallExpr::const_arg_iterator *args_end,
                    bool force_gvariant_pointer,
                    bool force_gvariantbuilder_pointer,
                    bool allow_maybe, CompilerInstance& compiler,
                    const StringLiteral *format_arg_str,
                    ASTContext& context,
                    bool consume_vararg)
{
	DEBUG ("Checking type string ‘" << *type_str << "’.");

	QualType expected_type;

	/* Reference: GVariant Type Strings. */
	switch (**type_str) {
	/* Variants */
	case 'v': /* GVariant* */
		/* Stricter validation is applied in
		 * _consume_variadic_argument(). */
		expected_type = context.VoidPtrTy;
		force_gvariant_pointer = true;
		break;
	/* Arrays */
	case 'a':
		/* Consume the ‘a’. */
		*type_str = *type_str + 1;

		/* Check and consume the type string for the array element
		 * type. */
		if (!_check_type_string (type_str, args_begin, args_end,
		                         force_gvariant_pointer,
		                         true,
		                         true,
		                         compiler, format_arg_str, context,
		                         false  /* don’t consume varargs */)) {
			return false;
		}

		/* Consume the single GVariantBuilder for the array. */
		return _consume_variadic_argument (context.VoidPtrTy,
		                                   args_begin, args_end,
		                                   force_gvariant_pointer,
		                                   true  /* force GVariantBuilder* */,
		                                   true  /* allow_maybe; FIXME: only for definite types */,
		                                   compiler,
		                                   format_arg_str, context,
		                                   consume_vararg);
	/* Maybe Types */
	case 'm':
		*type_str = *type_str + 1;  /* consume the ‘m’ */
		return _check_type_string (type_str, args_begin, args_end,
		                           force_gvariant_pointer,
		                           force_gvariantbuilder_pointer,
		                           true  /* allow_maybe */,
		                           compiler, format_arg_str, context,
		                           consume_vararg);
	/* Tuples */
	case '(':
		*type_str = *type_str + 1;  /* consume the opening bracket */

		while (**type_str != ')' && **type_str != '\0') {
			if (!_check_type_string (type_str, args_begin,
			                         args_end,
			                         force_gvariant_pointer,
			                         force_gvariantbuilder_pointer,
			                         allow_maybe, compiler,
			                         format_arg_str, context,
			                         consume_vararg)) {
				return false;
			}
		}

		if (**type_str != ')') {
			Debug::emit_error (
				"Invalid GVariant type string: tuple "
				"did not end with ‘)’.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		}

		*type_str = *type_str + 1;  /* consume the closing bracket */

		return true;
	case 'r': /* GVariant* of tuple type */
		/* Stricter validation is applied in
		 * _consume_variadic_argument().
		 *
		 * FIXME: Validate that the GVariant* has a tuple type. */
		expected_type = context.VoidPtrTy;
		force_gvariant_pointer = true;
		break;
	/* Dictionaries */
	case '{':
		*type_str = *type_str + 1;  /* consume the opening brace */

		if (**type_str == '}') {
			Debug::emit_error (
				"Invalid GVariant type string: dict did not "
				"contain exactly two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (!_check_basic_type_string (type_str, args_begin,
		                                      args_end,
		                                      force_gvariant_pointer,
		                                      force_gvariantbuilder_pointer,
		                                      allow_maybe, compiler,
		                                      format_arg_str, context,
		                                      consume_vararg)) {
			return false;
		}

		if (**type_str == '}') {
			Debug::emit_error (
				"Invalid GVariant type string: dict did not "
				"contain exactly two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (!_check_type_string (type_str, args_begin, args_end,
		                                force_gvariant_pointer,
		                                force_gvariantbuilder_pointer,
		                                allow_maybe, compiler,
		                                format_arg_str, context,
		                                consume_vararg)) {
			return false;
		}

		if (**type_str == '\0') {
			Debug::emit_error (
				"Invalid GVariant type string: dict "
				"did not end with ‘}’.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (**type_str != '}') {
			Debug::emit_error (
				"Invalid GVariant type string: dict "
				"contains more than two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		}

		*type_str = *type_str + 1;  /* consume the closing brace */

		return true;
	/* GVariant* */
	case '*': /* GVariant* of any type */
		/* Stricter validation is applied in
		 * _consume_variadic_argument(). */
		expected_type = context.VoidPtrTy;
		force_gvariant_pointer = true;
		break;
	default:
		/* Fall back to checking basic types. */
		return _check_basic_type_string (type_str, args_begin, args_end,
		                                 force_gvariant_pointer,
		                                 force_gvariantbuilder_pointer,
		                                 allow_maybe,
		                                 compiler, format_arg_str, context,
		                                 consume_vararg);
	}

	/* Consume the type string. */
	*type_str = *type_str + 1;

	return _consume_variadic_argument (expected_type,
	                                   args_begin, args_end,
	                                   force_gvariant_pointer,
	                                   force_gvariantbuilder_pointer,
	                                   allow_maybe, compiler,
	                                   format_arg_str, context,
	                                   consume_vararg);
}

/* Parse a single basic format string from the beginning of the string pointed
 * to by @format_str (i.e. *format_str). Consume any variadic parameters from
 * @args_begin as appropriate. This will emit errors where found.
 *
 * @format_str and @args_begin are updated as the format string and arguments
 * are consumed. */
static bool
_check_basic_format_string (const gchar **format_str,
                            CallExpr::const_arg_iterator *args_begin,
                            CallExpr::const_arg_iterator *args_end,
                            bool force_gvariant_pointer,
                            bool force_gvariantbuilder_pointer,
                            bool allow_maybe,
                            CompilerInstance& compiler,
                            const StringLiteral *format_arg_str,
                            ASTContext& context,
                            bool consume_vararg)
{
	DEBUG ("Checking format string ‘" << *format_str << "’.");

	/* Reference: GVariant Format Strings documentation, §Syntax. */
	switch (**format_str) {
	case '@':
		*format_str = *format_str + 1;  /* consume the ‘@’ */
		return _check_basic_type_string (format_str, args_begin,
		                                 args_end,
		                                 true  /* force GVariant */,
		                                 force_gvariantbuilder_pointer,
		                                 allow_maybe, compiler,
		                                 format_arg_str, context,
		                                 consume_vararg);
	case '?':
		/* Direct GVariant. Stricter checking is implemented later on,
		 * so we don’t just validate to VoidPtrTy. */
		*format_str = *format_str + 1;  /* consume the argument */
		return _consume_variadic_argument (context.VoidPtrTy,
		                                   args_begin, args_end,
		                                   true  /* force GVariant* */,
		                                   force_gvariantbuilder_pointer,
		                                   allow_maybe, compiler,
		                                   format_arg_str, context,
		                                   consume_vararg);
	case '&':
		/* Ignore it. */
		*format_str = *format_str + 1;
		return _check_basic_type_string (format_str, args_begin,
		                                 args_end,
		                                 force_gvariant_pointer,
		                                 force_gvariantbuilder_pointer,
		                                 allow_maybe, compiler,
		                                 format_arg_str, context,
		                                 consume_vararg);
	case '^':
		/* Various different hard-coded types. */
		*format_str = *format_str + 1;

		QualType expected_type;
		QualType char_array = context.getPointerType (context.CharTy);
		guint skip;

		/* Effectively hard-code the table from
		 * §Convenience Conversions. */
		if (strcmp (*format_str, "as") == 0 ||
		    strcmp (*format_str, "ao") == 0) {
			expected_type = context.getPointerType (char_array);
			skip = 2;
		} else if (strcmp (*format_str, "a&s") == 0 ||
		           strcmp (*format_str, "a&o") == 0 ||
		           strcmp (*format_str, "aay") == 0) {
			expected_type = context.getPointerType (char_array);
			skip = 3;
		} else if (strcmp (*format_str, "ay") == 0) {
			expected_type = char_array;
			skip = 2;
		} else if (strcmp (*format_str, "&ay") == 0) {
			expected_type = char_array;
			skip = 3;
		} else if (strcmp (*format_str, "a&ay") == 0) {
			expected_type = context.getPointerType (char_array);
			skip = 4;
		} else {
			/* TODO: error plus tests */
		}

		*format_str = *format_str + skip;

		return _consume_variadic_argument (expected_type, args_begin,
		                                   args_end,
		                                   force_gvariant_pointer,
		                                   force_gvariantbuilder_pointer,
		                                   allow_maybe, compiler,
		                                   format_arg_str, context,
		                                   consume_vararg);
	default:
		/* Assume it’s a type string. */
		return _check_basic_type_string (format_str, args_begin,
		                                 args_end,
		                                 force_gvariant_pointer,
		                                 force_gvariantbuilder_pointer,
		                                 allow_maybe, compiler,
		                                 format_arg_str, context,
		                                 consume_vararg);
	}
}

/* Parse a single format string from the beginning of the string pointed
 * to by @format_str (i.e. *format_str). Consume any variadic parameters from
 * @args_begin as appropriate. This will emit errors where found.
 *
 * @format_str and @args_begin are updated as the format string and arguments
 * are consumed. */
static bool
_check_format_string (const gchar **format_str,
                      CallExpr::const_arg_iterator *args_begin,
                      CallExpr::const_arg_iterator *args_end,
                      bool force_gvariant_pointer,
                      bool force_gvariantbuilder_pointer,
                      bool allow_maybe,
                      CompilerInstance& compiler,
                      const StringLiteral *format_arg_str,
                      ASTContext& context,
                      bool consume_vararg)
{
	DEBUG ("Checking format string ‘" << *format_str << "’.");

	/* Reference: GVariant Format Strings documentation, §Syntax. */
	switch (**format_str) {
	case '@':
		*format_str = *format_str + 1;  /* consume the ‘@’ */
		return _check_type_string (format_str, args_begin, args_end,
		                           true  /* force GVariant */,
		                           force_gvariantbuilder_pointer,
		                           allow_maybe, compiler,
		                           format_arg_str, context,
		                           consume_vararg);
	case 'm':
		*format_str = *format_str + 1;  /* consume the ‘m’ */
		return _check_format_string (format_str, args_begin, args_end,
		                             force_gvariant_pointer,
		                             force_gvariantbuilder_pointer,
		                             true  /* allow maybe */,
		                             compiler, format_arg_str, context,
		                             consume_vararg);
	case '*':
	case '?':
	case 'r':
		/* Direct GVariants. Stricter checking is implemented later on,
		 * so we don’t just validate to VoidPtrTy. */
		*format_str = *format_str + 1;  /* consume the argument */
		return _consume_variadic_argument (context.VoidPtrTy,
		                                   args_begin, args_end,
		                                   true  /* force GVariant* */,
		                                   force_gvariantbuilder_pointer,
		                                   allow_maybe, compiler,
		                                   format_arg_str, context,
		                                   consume_vararg);
	case '(':
		*format_str = *format_str + 1;  /* consume the opening bracket */

		while (**format_str != ')' && **format_str != '\0') {
			if (!_check_format_string (format_str, args_begin,
			                           args_end,
			                           force_gvariant_pointer,
			                           force_gvariantbuilder_pointer,
			                           allow_maybe, compiler,
			                           format_arg_str, context,
			                           consume_vararg)) {
				return false;
			}
		}

		if (**format_str != ')') {
			Debug::emit_error (
				"Invalid GVariant format string: tuple "
				"did not end with ‘)’.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		}

		*format_str = *format_str + 1;  /* consume the closing bracket */

		return true;
	case '{':
		*format_str = *format_str + 1;  /* consume the opening brace */

		if (**format_str == '}') {
			Debug::emit_error (
				"Invalid GVariant format string: dict did not "
				"contain exactly two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (!_check_basic_format_string (format_str, args_begin,
		                                        args_end,
		                                        force_gvariant_pointer,
		                                        force_gvariantbuilder_pointer,
		                                        allow_maybe, compiler,
		                                        format_arg_str, context,
		                                        consume_vararg)) {
			return false;
		}

		if (**format_str == '}') {
			Debug::emit_error (
				"Invalid GVariant format string: dict did not "
				"contain exactly two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (!_check_format_string (format_str, args_begin,
		                                  args_end,
		                                  force_gvariant_pointer,
		                                  force_gvariantbuilder_pointer,
		                                  allow_maybe, compiler,
		                                  format_arg_str, context,
		                                  consume_vararg)) {
			return false;
		}

		if (**format_str == '\0') {
			Debug::emit_error (
				"Invalid GVariant format string: dict "
				"did not end with ‘}’.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		} else if (**format_str != '}') {
			Debug::emit_error (
				"Invalid GVariant format string: dict "
				"contains more than two elements.",
				compiler,
				format_arg_str->getLocStart ());
			return false;
		}

		*format_str = *format_str + 1;  /* consume the closing brace */

		return true;
	case '&':
		/* Ignore it. */
		*format_str = *format_str + 1;
		return _check_type_string (format_str, args_begin, args_end,
		                           force_gvariant_pointer,
		                           force_gvariantbuilder_pointer,
		                           allow_maybe, compiler,
		                           format_arg_str, context,
		                           consume_vararg);
	case '^':
		/* Handled by the basic format string parser. */
		return _check_basic_format_string (format_str, args_begin,
		                                   args_end,
		                                   force_gvariant_pointer,
		                                   force_gvariantbuilder_pointer,
		                                   allow_maybe, compiler,
		                                   format_arg_str, context,
		                                   consume_vararg);
	default:
		/* Assume it’s a type string. */
		return _check_type_string (format_str, args_begin, args_end,
		                           force_gvariant_pointer,
		                           force_gvariantbuilder_pointer,
		                           allow_maybe, compiler,
		                           format_arg_str, context,
		                           consume_vararg);
	}
}

/* Build a GVariant format string to represent the given type, or return NULL if
 * no representation is known. The returned value must be freed using
 * g_free(). */
static gchar *
_gvariant_format_string_for_type (QualType type)
{
	/* TODO: Return the format string for a basic type */
	return NULL;
}

/* Check a GVariant function call which passes a format parameter. Validate the
 * format parameter string, and if the function takes varargs, validate their
 * types against that parameter.
 *
 * If the format string is not a string literal, we can’t check anything. */
static bool
_check_gvariant_format_param (const CallExpr& call,
                              const FunctionDecl &func,
                              const VariantFuncInfo *func_info,
                              CompilerInstance& compiler,
                              ASTContext& context)
{
	/* Grab the format parameter string. */
	const Expr *format_arg = call.getArg (func_info->format_param_index)->IgnoreParenImpCasts ();

	DEBUG ("Checking GVariant format strings in " << func.getNameAsString () << "().");

	const StringLiteral *format_arg_str = dyn_cast<StringLiteral> (format_arg);
	if (format_arg_str == NULL) {
		Debug::emit_warning (
			"Non-literal GVariant format string in call to " +
			func.getNameAsString () +
			"(). Cannot check format string correctness.",
			compiler,
			format_arg->getLocStart ());
		return false;
	}

	/* Check the string. Parse it hand-in-hand with iterating through the
	 * varargs list. */
	DEBUG ("Checking GVariant format string ‘" <<
	       format_arg_str->getString () << "’ with " <<
	       call.getNumArgs () << " variadic arguments.");

	const gchar *format_str = format_arg_str->getString ().data ();
	CallExpr::const_arg_iterator args_begin = call.arg_begin ();
	CallExpr::const_arg_iterator args_end = call.arg_end ();

	/* Skip up to the varargs. If args_begin points to a va_list, the rest
	 * of the code will ignore it. */
	for (unsigned int i = 0; i < func_info->first_vararg_param_index; i++)
		++args_begin;

	if (!_check_format_string (&format_str, &args_begin, &args_end,
	                           false  /* don’t force GVariant */,
	                           false  /* don’t force GVariantBuilder */,
	                           false  /* disallow maybe */,
	                           compiler, format_arg_str, context,
	                           !func_info->uses_va_list)) {
		return false;
	}

	/* Sanity check that we’ve consumed all format strings. If not, the
	 * user has probably forgotten to add tuple brackets around their format
	 * string. Don’t emit any error messages about unpaired variadic
	 * arguments because that would just confuse things. */
	if (*format_str != '\0') {
		gchar *error;

		error = g_strdup_printf ("Unexpected GVariant format strings "
		                         "‘%s’ with unpaired arguments. If "
		                         "using multiple format strings, they "
		                         "should be enclosed in brackets to "
		                         "create a tuple (e.g. ‘(%s)’).",
		                         format_str,
		                         format_arg_str->getString ().data ());
		Debug::emit_error (error, compiler,
		                   format_arg_str->getLocStart ());
		g_free (error);

		return false;
	}

	/* Sanity check that we’ve consumed all arguments. */
	bool retval = true;

	for (; !func_info->uses_va_list && args_begin != args_end;
	     ++args_begin) {
		const Expr *arg = *args_begin;
		gchar *error;
		gchar *error_format_str;

		error_format_str = _gvariant_format_string_for_type (arg->getType ());

		if (error_format_str != NULL) {
			error = g_strdup_printf (
				"Unexpected GVariant variadic argument of type "
				"‘%s’. A ‘%s’ GVariant format string should be "
				"added to the format argument to use it.",
				arg->getType ().getAsString ().c_str (),
				error_format_str);
		} else {
			error = g_strdup_printf (
				"Unexpected GVariant variadic argument of type "
				"‘%s’. A GVariant format string should be "
				"added to the format argument to use it, but "
				"there is no known GVariant representation of "
				"the argument’s type. The argument must be "
				"serialized to a GVariant-representable type "
				"first.",
				arg->getType ().getAsString ().c_str ());
		}

		Debug::emit_error (error, compiler, arg->getLocStart ());
		g_free (error);

		retval = false;
	}

	return retval;
}

void
GVariantConsumer::HandleTranslationUnit (ASTContext& context)
{
	this->_visitor.TraverseDecl (context.getTranslationUnitDecl ());
}

/* Note: Specifically overriding the Traverse* method here to re-implement
 * recursion to child nodes. */
bool
GVariantVisitor::VisitCallExpr (CallExpr* expr)
{
	const VariantFuncInfo *func_info;

	/* Can only handle direct function calls (i.e. not calling dereferenced
	 * function pointers). */
	const FunctionDecl *func = expr->getDirectCallee ();
	if (func == NULL)
		return true;

	/* We’re only interested in functions which handle GVariants. */
	func_info = _func_uses_gvariant_format (*func);
	if (func_info == NULL)
		return true;

	/* Check the format parameter. */
	_check_gvariant_format_param (*expr, *func, func_info, this->_compiler,
	                              func->getASTContext ());

	return true;
}
