/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * gnome-clang
 * Copyright © 2013 Collabora Ltd.
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
 *     Philip Withnall <philip.withnall@collabora.co.uk>
 */

#include <clang/Frontend/FrontendPluginRegistry.h>
#include <clang/AST/AST.h>
#include <clang/AST/ASTConsumer.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <llvm/Support/raw_ostream.h>

#include "debug.h"
#include "gir-attributes.h"
#include "gassert-attributes.h"
#include "gvariant-checker.h"
#include "nullability-checker.h"

using namespace clang;

namespace {

/**
 * Plugin core.
 */
class GnomeAction : public PluginASTAction {
private:
	std::shared_ptr<GirManager> _gir_manager =
		std::make_shared<GirManager> ();

protected:
	/* Note: This is called before ParseArgs, and must transfer ownership
	 * of the ASTConsumer. The GnomeAction object is destroyed immediately
	 * after this function call returns, so must be careful not to retain
	 * state which is needed by the consumers. */
	ASTConsumer *
	CreateASTConsumer (CompilerInstance &compiler, llvm::StringRef in_file)
	{
		std::vector<ASTConsumer*> consumers;
		consumers.push_back (
			new GirAttributesConsumer (this->_gir_manager));
		consumers.push_back (new GAssertAttributesConsumer ());
		consumers.push_back (
			new NullabilityConsumer (compiler,
			                         this->_gir_manager));
		consumers.push_back (
			new GVariantConsumer (compiler));
		consumers.push_back (
			new GirAttributesChecker (compiler,
			                          this->_gir_manager));

		return new MultiplexConsumer (consumers);
	}

private:
	bool
	_load_typelib (const CompilerInstance &CI,
	               const std::string& gi_namespace_and_version)
	{
		std::string::size_type p = gi_namespace_and_version.find ("-");

		if (p == std::string::npos) {
			/* Ignore it — probably a non-typelib file. */
			return false;
		}

		std::string gi_namespace =
			gi_namespace_and_version.substr (0, p);
		std::string gi_version =
			gi_namespace_and_version.substr (p + 1);

		DEBUG ("Loading typelib " + gi_namespace + " " + gi_version);

		/* Load the repository. */
		GError *error = NULL;

		this->_gir_manager.get ()->load_namespace (gi_namespace,
		                                           gi_version,
		                                           &error);
		if (error != NULL &&
		    !g_error_matches (error, G_IREPOSITORY_ERROR,
		                      G_IREPOSITORY_ERROR_NAMESPACE_VERSION_CONFLICT)) {
			DiagnosticsEngine &d = CI.getDiagnostics ();
			unsigned int id = d.getCustomDiagID (
				DiagnosticsEngine::Error,
				"Error loading GI repository ‘" + gi_namespace +
				"’ (version " + gi_version + "): " +
				error->message);
			d.Report (id);

			g_error_free (error);

			return false;
		}

		g_clear_error (&error);

		return true;
	}

	/* Load all the GI typelibs we can find. This shouldn’t take long, and
	 * saves the user having to specify which typelibs to use (or us having
	 * to try and work out which ones the user’s code uses by looking at
	 * #included files). */
	bool
	_load_gi_repositories (const CompilerInstance &CI)
	{
		GSList/*<unowned string>*/ *typelib_paths, *l;

		typelib_paths = g_irepository_get_search_path ();

		for (l = typelib_paths; l != NULL; l = l->next) {
			GDir *dir;
			const gchar *typelib_path, *typelib_filename;
			GError *error = NULL;

			typelib_path = (const gchar *) l->data;
			dir = g_dir_open (typelib_path, 0, &error);

			if (error != NULL) {
				/* Warn about the bogus include path and
				 * continue. */
				gchar *error_msg;
				DiagnosticsEngine &d = CI.getDiagnostics ();

				error_msg = g_strdup_printf (
					"Error opening typelib path ‘%s’: %s",
					typelib_path, error->message);

				unsigned int id = d.getCustomDiagID (
					DiagnosticsEngine::Warning, error_msg);
				d.Report (id);

				g_free (error_msg);

				continue;
			}

			while ((typelib_filename = g_dir_read_name (dir)) != NULL) {
				/* Load the typelib. Ignore failure. */

				std::string _typelib_filename (typelib_filename);
				std::string::size_type last_dot = _typelib_filename.find_last_of (".");
				if (last_dot == std::string::npos) {
					/* No ‘.typelib’ suffix — ignore. */
					continue;
				}

				std::string gi_namespace_and_version = _typelib_filename.substr (0, last_dot);
				this->_load_typelib (CI, gi_namespace_and_version);
			}

			g_dir_close (dir);
		}

		return true;
	}

protected:
	/* Parse command line arguments for the plugin. Note: This is called
	 * after CreateASTConsumer. */
	bool
	ParseArgs (const CompilerInstance &CI,
	           const std::vector<std::string>& args)
	{
		/* Load all typelibs. */
		this->_load_gi_repositories (CI);

		for (std::vector<std::string>::const_iterator it = args.begin();
		     it != args.end (); ++it) {
			std::string arg = *it;

			if (arg == "--help") {
				this->PrintHelp (llvm::errs ());
			}
		}

		return true;
	}

	/* Print plugin-specific help. */
	void
	PrintHelp (llvm::raw_ostream& out)
	{
		/* TODO: i18n */
		out << "A plugin to enable extra static analysis checks and "
		       "warnings for C code which uses GLib, by making use of "
		       "GIR metadata and other GLib coding conventions.\n"
		       "\n"
		       "Usage:\n"
		       "    clang -cc1 -load /path/to/libclang-gnome.so "
		           "-add-plugin gnome\n";
	}

	bool
	shouldEraseOutputFiles ()
	{
		/* TODO: Make this conditional on an error occurring. */
		return false;
	}
};


/* Register the plugin with LLVM. */
static FrontendPluginRegistry::Add<GnomeAction>
X("gnome", "add attributes and warnings using GNOME-specific metadata");

} /* namespace */
