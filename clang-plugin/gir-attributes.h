/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * Tartan
 * Copyright © 2013 Collabora Ltd.
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
 *     Philip Withnall <philip.withnall@collabora.co.uk>
 */

#ifndef TARTAN_GIR_ATTRIBUTES_H
#define TARTAN_GIR_ATTRIBUTES_H

#include <clang/AST/AST.h>
#include <clang/AST/ASTConsumer.h>
#include <clang/Frontend/CompilerInstance.h>

#include <girepository.h>

#include "gir-manager.h"

using namespace clang;

class GirAttributesConsumer : public ASTConsumer {

public:
	explicit GirAttributesConsumer (
		std::shared_ptr<const GirManager> gir_manager) :
		_gir_manager (gir_manager) {}

private:
	std::shared_ptr<const GirManager> _gir_manager;

	void _handle_function_decl (FunctionDecl& func);
public:
	virtual bool HandleTopLevelDecl (DeclGroupRef decl_group);
};


class GirAttributesChecker : public ASTConsumer {

public:
	explicit GirAttributesChecker (
		CompilerInstance& compiler,
		std::shared_ptr<const GirManager> gir_manager) :
		_compiler (compiler), _gir_manager (gir_manager) {}

private:
	CompilerInstance& _compiler;
	std::shared_ptr<const GirManager> _gir_manager;

	void _handle_function_decl (FunctionDecl& func);
public:
	virtual bool HandleTopLevelDecl (DeclGroupRef decl_group);
};

#endif /* !TARTAN_GIR_ATTRIBUTES_H */
