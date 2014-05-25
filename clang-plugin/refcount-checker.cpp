/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * Tartan
 * Copyright © 2014 Philip Withnall
 *
 * Tartan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tartan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tartan.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Philip Withnall <philip@tecnocode.co.uk>
 */

/**
 * RefcountChecker:
 *
 * TODO
 */

#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>

#include "refcount-checker.h"

namespace tartan {

using namespace clang;

/* TODO: docs */
struct RefcountState {
private:
	int _delta;
	bool _is_returned;

	RefcountState (int delta, bool is_returned) :
		_delta (delta), _is_returned (is_returned) {}

public:
	bool is_valid () const { return this->_delta >= 0; }
	bool is_dead () const { return this->_delta == 0; }

	static RefcountState constructed () {
		return RefcountState (1, false);
	}

	static RefcountState returned (const RefcountState *old) {
		if (old == NULL) {
			return RefcountState (0, true);
		}

		assert (!old->_is_returned);
		return RefcountState (old->_delta, true);
	}

	static RefcountState reffed (const RefcountState *old) {
		if (old == NULL) {
			return RefcountState (1, false);
		}

		assert (!old->_is_returned);
		return RefcountState (old->_delta + 1, false);
	}

	static RefcountState unreffed (const RefcountState *old) {
		if (old == NULL) {
			return RefcountState (-1, false);
		}

		assert (!old->_is_returned);
		return RefcountState (old->_delta - 1, false);
	}

	bool operator == (const RefcountState &other) const {
		return (other._delta == this->_delta &&
		        other._is_returned == this->_is_returned);
	}

	/* TODO: what's this for? */
	void Profile (llvm::FoldingSetNodeID &id) const {
		id.AddInteger (this->_delta);
	}
};

} /* namespace tartan */

/* Track objects and their refcounts in a map stored on the ProgramState.
 * The namespacing is necessary to be able to specialise a Clang template. */
REGISTER_MAP_WITH_PROGRAMSTATE (RefcountMap, clang::ento::SymbolRef,
                                tartan::RefcountState)

namespace tartan {

#if 0
RefcountChecker::RefcountChecker ()
{
	// TODO: initialise bug types
//  DoubleCloseBugType.reset(new BugType("Double fclose",
//                                       "Unix Stream API Error"));
// TODO: suppress leak bugs on sinks?
}
#endif

void
RefcountChecker::checkPostStmt (const CallExpr *call,
                                CheckerContext &context) const
{
	// TODO: handle arbitrary functions
	// TODO: handle constructors
	const ProgramStateRef state = context.getState ();
	const LocationContext *location_context = context.getLocationContext ();
	const Expr *callee = call->getCallee ();
	const FunctionDecl *decl =
		state->getSVal (callee, location_context).getAsFunctionDecl ();

	this->_initialise_identifiers (context.getASTContext ());

	IdentifierInfo *ident = decl->getIdentifier ();
	llvm::errs () << "bzzzt\n";
	if (ident == this->_g_object_ref_identifier &&
	    call->getNumArgs () == 1) {
		this->_check_g_object_ref (call, context);
		return;
	} else if (ident == this->_g_object_unref_identifier &&
	           call->getNumArgs () == 1) {
		this->_check_g_object_unref (call, context);
		return;
	}
}

void
RefcountChecker::_check_g_object_ref (const CallExpr *call,
                                      CheckerContext &context) const
{
	ProgramStateRef state = context.getState ();
	const LocationContext *location_context = context.getLocationContext ();
	llvm::errs () << "bzzzt ref\n";
	/* Get the symbolic value for the object. */
	const Expr *arg_expr = call->getArg (0);
	SVal obj_sval = state->getSVal (arg_expr, location_context);
	SymbolRef obj = obj_sval.getAsSymbol ();

	if (obj == NULL) {
		/* TODO: warning? */
		return;
	}

	/* Add an artificial symbol dependency between the object parameter and
	 * the return value for g_object_ref(). This is essentially modelling
	 * the behaviour of g_object_ref() as:
	 *     GObject *g_object_ref (GObject *x) { return x; }
	 * (ignoring the side effect of increasing X's reference count). */
	state = state->BindExpr (call, location_context, obj_sval);

	/* Generate a new transition in the exploded graph, adding a reference
	 * to the object. */
	const RefcountState *r_state = state->get<RefcountMap> (obj);
	state = state->set<RefcountMap> (obj, RefcountState::reffed (r_state));
	context.addTransition (state);
}

void
RefcountChecker::_check_g_object_unref (const CallExpr *call,
                                        CheckerContext &context) const
{
	ProgramStateRef state = context.getState ();
	const LocationContext *location_context = context.getLocationContext ();
	llvm::errs () << "bzzzt unref\n";
	/* Get the symbolic value for the object. */
	const Expr *arg_expr = call->getArg (0);
	SVal obj_sval = state->getSVal (arg_expr, location_context);
	SymbolRef obj = obj_sval.getAsSymbol ();

	if (obj == NULL) {
		/* TODO: warning? */
		return;
	}

	/* Generate a new transition in the exploded graph, removing a
	 * reference from the object. */
	const RefcountState *r_state = state->get<RefcountMap> (obj);
	RefcountState new_state = RefcountState::unreffed (r_state);

	if (!new_state.is_valid ()) {
		ExplodedNode *node = context.generateSink ();

		if (node == NULL) {
			return;
		}

		this->_initialise_bug_reports ();

		BugReport *report = new BugReport (*this->_unref_bug,
		                                   this->_unref_bug->getDescription(),
		                                   node);
		context.emitReport (report);

		return;
	}

	state = state->set<RefcountMap> (obj, RefcountState::unreffed (r_state));
	context.addTransition (state);
}

#if 0
TODO
static bool isLeaked(SymbolRef Sym, const StreamState &SS,
                     bool IsSymDead, ProgramStateRef State) {
  if (IsSymDead && SS.isOpened()) {
    // If a symbol is NULL, assume that fopen failed on this path.
    // A symbol should only be considered leaked if it is non-null.
    ConstraintManager &CMgr = State->getConstraintManager();
    ConditionTruthVal OpenFailed = CMgr.isNull(State, Sym);
    return !OpenFailed.isConstrainedTrue();
  }
  return false;
}

void SimpleStreamChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolVector LeakedStreams;
  StreamMapTy TrackedStreams = State->get<StreamMap>();
  for (StreamMapTy::iterator I = TrackedStreams.begin(),
                             E = TrackedStreams.end(); I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SymReaper.isDead(Sym);

    // Collect leaked symbols.
    if (isLeaked(Sym, I->second, IsSymDead, State))
      LeakedStreams.push_back(Sym);

    // Remove the dead symbol from the streams map.
    if (IsSymDead)
      State = State->remove<StreamMap>(Sym);
  }

  ExplodedNode *N = C.addTransition(State);
  reportLeaks(LeakedStreams, C, N);
}

void SimpleStreamChecker::reportDoubleClose(SymbolRef FileDescSym,
                                            const CallEvent &Call,
                                            CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateSink();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  BugReport *R = new BugReport(*DoubleCloseBugType,
      "Closing a previously closed file stream", ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(FileDescSym);
  C.emitReport(R);
}

// If the pointer we are tracking escaped, do not track the symbol as
// we cannot reason about it anymore.
ProgramStateRef
SimpleStreamChecker::checkPointerEscape(ProgramStateRef State,
                                        const InvalidatedSymbols &Escaped,
                                        const CallEvent *Call,
                                        PointerEscapeKind Kind) const {
  // If we know that the call cannot close a file, there is nothing to do.
  if (Kind == PSK_DirectEscapeOnCall && guaranteedNotToCloseFile(*Call)) {
    return State;
  }

  for (InvalidatedSymbols::const_iterator I = Escaped.begin(),
                                          E = Escaped.end();
                                          I != E; ++I) {
    SymbolRef Sym = *I;

    // The symbol escaped. Optimistically, assume that the corresponding file
    // handle will be closed somewhere else.
    State = State->remove<StreamMap>(Sym);
  }
  return State;
}
#endif

void
RefcountChecker::_initialise_identifiers (ASTContext &context) const
{
	if (this->_g_object_ref_identifier != NULL) {
		return;
	}

	this->_g_object_ref_identifier = &context.Idents.get ("g_object_ref");
	this->_g_object_unref_identifier =
		&context.Idents.get ("g_object_unref");
}

void
RefcountChecker::_initialise_bug_reports () const
{
	if (this->_unref_bug) {
		return;
	}

	this->_unref_bug.reset (new BuiltinBug ("Unowned unref",
	                                        "Try to unref an object "
	                                        "you do not have ownership "
	                                        "of. Cause eventual "
	                                        "double-unref."));
}

} /* namespace tartan */
