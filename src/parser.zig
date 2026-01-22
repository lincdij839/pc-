// PC Language Parser
const std = @import("std");
const Token = @import("token.zig").Token;
const TokenKind = @import("token.zig").TokenKind;
const ast = @import("ast.zig");
const Node = ast.Node;

pub const ParserError = error{
    UnexpectedToken,
    UnexpectedEof,
    OutOfMemory,
    Overflow,
    InvalidCharacter,
};

pub const Parser = struct {
    tokens: []const Token,
    pos: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, tokens: []const Token) Parser {
        return .{
            .tokens = tokens,
            .pos = 0,
            .allocator = allocator,
        };
    }

    fn current(self: *const Parser) Token {
        if (self.pos < self.tokens.len) {
            return self.tokens[self.pos];
        }
        return self.tokens[self.tokens.len - 1]; // EOF
    }

    fn peek(self: *const Parser, offset: usize) Token {
        const pos = self.pos + offset;
        if (pos < self.tokens.len) {
            return self.tokens[pos];
        }
        return self.tokens[self.tokens.len - 1];
    }

    fn advance(self: *Parser) void {
        if (self.pos < self.tokens.len - 1) {
            self.pos += 1;
        }
    }

    fn match(self: *Parser, kind: TokenKind) bool {
        if (self.current().kind == kind) {
            self.advance();
            return true;
        }
        return false;
    }

    fn expect(self: *Parser, kind: TokenKind) !Token {
        const tok = self.current();
        if (tok.kind != kind) {
            std.debug.print("Expected {s}, got {s}\n", .{ @tagName(kind), @tagName(tok.kind) });
            return ParserError.UnexpectedToken;
        }
        self.advance();
        return tok;
    }

    fn skipNewlines(self: *Parser) void {
        while (self.match(.Newline)) {}
    }

    pub fn parseProgram(self: *Parser) !*Node {
        const program = try ast.createNode(self.allocator, .Program);

        while (self.current().kind != .Eof) {
            self.skipNewlines();
            if (self.current().kind == .Eof) break;

            const stmt = try self.parseStatement();
            try program.Program.statements.append(stmt);

            self.skipNewlines();
        }

        return program;
    }

    fn parseStatement(self: *Parser) !*Node {
        return switch (self.current().kind) {
            .Def => self.parseFunctionDef(),
            .Return => self.parseReturn(),
            .If => self.parseIf(),
            .While => self.parseWhile(),
            .For => self.parseFor(),
            else => self.parseExpressionStatement(),
        };
    }

    fn parseFunctionDef(self: *Parser) !*Node {
        _ = try self.expect(.Def);
        const name_tok = try self.expect(.Identifier);

        _ = try self.expect(.LeftParen);
        
        // Parse parameters
        var params = std.ArrayList(*Node).init(self.allocator);
        while (self.current().kind != .RightParen and self.current().kind != .Eof) {
            const param_name = try self.expect(.Identifier);
            const param_node = try ast.createIdentifier(self.allocator, param_name.lexeme);
            
            // Optional type annotation for parameter
            if (self.match(.Colon)) {
                // Skip type for now (e.g., i32, str)
                _ = self.advance();
            }
            
            try params.append(param_node);
            
            if (!self.match(.Comma)) break;
        }
        _ = try self.expect(.RightParen);

        // Optional return type
        var return_type: ?*Node = null;
        if (self.match(.Arrow)) {
            // Parse return type (e.g., i32, str)
            if (self.current().kind == .Identifier or 
                self.current().kind == .I32 or self.current().kind == .Str) {
                const type_tok = self.current();
                self.advance();
                return_type = try ast.createIdentifier(self.allocator, type_tok.lexeme);
            }
        }

        _ = try self.expect(.Colon);
        self.skipNewlines();

        // Parse body - parse indented block
        const body = try self.parseBlock();

        const node = try self.allocator.create(Node);
        node.* = Node{ .FunctionDef = .{
            .name = name_tok.lexeme,
            .params = params,
            .return_type = return_type,
            .body = body,
        } };
        return node;
    }

                fn isBlockTerminator(self: *Parser) bool {
                    const tok = self.current();
                    return tok.kind == .Def or 
                        tok.kind == .Class or
                        tok.kind == .Elif or
                        tok.kind == .Else or
                        tok.kind == .Eof;
                }

                fn parseBlock(self: *Parser) ParserError!*Node {
                    const body = try ast.createNode(self.allocator, .Block);
                    
                    while (!self.isBlockTerminator()) {
                        // Handle newlines
                        if (self.current().kind == .Newline) {
                            self.advance();
                            // If after newlines we see a terminator, stop
                            if (self.isBlockTerminator()) {
                                break;
                            }
                            continue;
                        }
                        
                        const stmt = try self.parseStatement();
                        try body.Block.statements.append(stmt);
                        self.skipNewlines();
                    }
                    
                    return body;
                }

                fn parseReturn(self: *Parser) !*Node {
                    _ = try self.expect(.Return);

                    const value = if (self.current().kind != .Newline and self.current().kind != .Eof)
                        try self.parseExpression()
                    else
                        null;

                    const node = try self.allocator.create(Node);
                    node.* = Node{ .ReturnStatement = .{ .value = value } };
                    return node;
                }

                fn parseIf(self: *Parser) !*Node {
                    _ = try self.expect(.If);
                    const condition = try self.parseExpression();
                    _ = try self.expect(.Colon);
                    self.skipNewlines();

                    // Parse then block
                    const then_branch = try self.parseBlock();
                    
                    // Check for elif/else
                    var else_branch: ?*Node = null;
                    if (self.current().kind == .Elif or self.current().kind == .Else) {
                        if (self.match(.Elif)) {
                            // elif is just another if statement
                            else_branch = try self.parseIf();
                        } else if (self.match(.Else)) {
                            _ = try self.expect(.Colon);
                            self.skipNewlines();
                            else_branch = try self.parseBlock();
                        }
                    }

                    const node = try self.allocator.create(Node);
                    node.* = Node{ .IfStatement = .{
                        .condition = condition,
                        .then_branch = then_branch,
                        .else_branch = else_branch,
                    } };
                    return node;
                }

                fn parseWhile(self: *Parser) !*Node {
                    _ = try self.expect(.While);
                    const condition = try self.parseExpression();
                    _ = try self.expect(.Colon);
                    self.skipNewlines();
                    
                    const body = try self.parseBlock();

                    const node = try self.allocator.create(Node);
                    node.* = Node{ .WhileLoop = .{
                        .condition = condition,
                        .body = body,
                    } };
                    return node;
                }

                fn parseFor(self: *Parser) !*Node {
                    _ = try self.expect(.For);
                    const iterator = try self.parsePrimary();
                    _ = try self.expect(.In);
                    const iterable = try self.parseExpression();
                    _ = try self.expect(.Colon);
                    self.skipNewlines();
                    
                    const body = try self.parseBlock();

                    const node = try self.allocator.create(Node);
                    node.* = Node{ .ForLoop = .{
                        .iterator = iterator,
                        .iterable = iterable,
                        .body = body,
                    } };
                    return node;
                }

                fn parseExpressionStatement(self: *Parser) !*Node {
                    const expr = try self.parseExpression();

                    // Check for type annotation (e.g., x: i32 = 10)
                    if (self.match(.Colon)) {
                        // Skip type annotation
                        _ = self.advance();
                        
                        // Now expect assignment
                        if (self.match(.Equal)) {
                            const value = try self.parseExpression();
                            const node = try self.allocator.create(Node);
                            node.* = Node{ .VariableDecl = .{ 
                                .name = if (expr.* == .Identifier) expr.Identifier.name else "unknown",
                                .type_annotation = null, // TODO: store type
                                .initializer = value 
                            } };
                            return node;
                        }
                    }

                    // Check for regular assignment
                    if (self.match(.Equal)) {
                        const value = try self.parseExpression();
                        const node = try self.allocator.create(Node);
                        node.* = Node{ .Assignment = .{ .target = expr, .value = value } };
                        return node;
                    }

                    return expr;
                }

                fn parseExpression(self: *Parser) ParserError!*Node {
                    return try self.parseBinaryOp();
                }

                fn parseBinaryOp(self: *Parser) ParserError!*Node {
                    var left = try self.parsePrimary();

                    while (true) {
                        const tok = self.current();
                        const is_operator = tok.kind == .Plus or tok.kind == .Minus or
                            tok.kind == .Star or tok.kind == .Slash or
                            tok.kind == .EqualEqual or tok.kind == .NotEqual or
                            tok.kind == .Less or tok.kind == .Greater;

                        if (!is_operator) break;

                        // Get the operator as a string
                        const op_str = switch (tok.kind) {
                            .Plus => "+",
                            .Minus => "-",
                            .Star => "*",
                            .Slash => "/",
                            .EqualEqual => "==",
                            .NotEqual => "!=",
                            .Less => "<",
                            .Greater => ">",
                            else => "?",
                        };

                        self.advance();
                        const right = try self.parsePrimary();
                        left = try ast.createBinaryOp(self.allocator, op_str, left, right);
                    }

                    return left;
                }

                fn parsePrimary(self: *Parser) ParserError!*Node {
                    const tok = self.current();
                    var node: *Node = undefined;

                    switch (tok.kind) {
                        .Integer => {
                            self.advance();
                            // Detect base from lexeme
                            var value: i64 = 0;
                            if (tok.lexeme.len > 2 and tok.lexeme[0] == '0') {
                                const prefix = tok.lexeme[1];
                                if (prefix == 'x' or prefix == 'X') {
                                    // Hexadecimal
                                    value = try std.fmt.parseInt(i64, tok.lexeme[2..], 16);
                                } else if (prefix == 'o' or prefix == 'O') {
                                    // Octal
                                    value = try std.fmt.parseInt(i64, tok.lexeme[2..], 8);
                                } else if (prefix == 'b' or prefix == 'B') {
                                    // Binary
                                    value = try std.fmt.parseInt(i64, tok.lexeme[2..], 2);
                                } else {
                                    // Decimal
                                    value = try std.fmt.parseInt(i64, tok.lexeme, 10);
                                }
                            } else {
                                // Decimal
                                value = try std.fmt.parseInt(i64, tok.lexeme, 10);
                            }
                            node = try ast.createInt(self.allocator, value);
                        },
                        .String => {
                            self.advance();
                            const str_node = try self.allocator.create(Node);
                            str_node.* = Node{ .LiteralString = .{ .value = tok.lexeme } };
                            node = str_node;
                        },
                        .True, .False => {
                            self.advance();
                            const bool_node = try self.allocator.create(Node);
                            bool_node.* = Node{ .LiteralBool = .{ .value = (tok.kind == .True) } };
                            node = bool_node;
            },
            .Identifier => {
                self.advance();
                // Check for function call
                if (self.current().kind == .LeftParen) {
                    _ = try self.expect(.LeftParen);
                    const call = try ast.createFunctionCall(self.allocator, try ast.createIdentifier(self.allocator, tok.lexeme));

                    // Parse arguments
                    while (self.current().kind != .RightParen) {
                        const arg = self.parseExpression() catch |err| return err;
                        try call.FunctionCall.arguments.append(arg);

                        if (!self.match(.Comma)) break;
                    }

                    _ = try self.expect(.RightParen);
                    node = call;
                } else {
                    node = try ast.createIdentifier(self.allocator, tok.lexeme);
                }
            },
            .LeftParen => {
                _ = try self.expect(.LeftParen);
                node = try self.parseExpression();
                _ = try self.expect(.RightParen);
            },
            .LeftBracket => {
                node = try self.parseListLiteral();
            },
            .LeftBrace => {
                node = try self.parseDictLiteral();
            },
            else => {
                std.debug.print("Unexpected token in expression: {s}\n", .{@tagName(tok.kind)});
                return ParserError.UnexpectedToken;
            },
        }

        // Handle index access: list[0]
        while (self.current().kind == .LeftBracket) {
            _ = try self.expect(.LeftBracket);
            const index = try self.parseExpression();
            _ = try self.expect(.RightBracket);
            const access_node = try self.allocator.create(Node);
            access_node.* = Node{ .IndexAccess = .{ .object = node, .index = index } };
            node = access_node;
        }

        return node;
    }

    fn parseListLiteral(self: *Parser) !*Node {
        _ = try self.expect(.LeftBracket);
        const list = try ast.createNode(self.allocator, .LiteralList);

        while (self.current().kind != .RightBracket and self.current().kind != .Eof) {
            const elem = try self.parseExpression();
            try list.LiteralList.elements.append(elem);
            if (!self.match(.Comma)) break;
        }

        _ = try self.expect(.RightBracket);
        return list;
    }

    fn parseDictLiteral(self: *Parser) !*Node {
        _ = try self.expect(.LeftBrace);
        const dict = try ast.createNode(self.allocator, .LiteralDict);

        while (self.current().kind != .RightBrace and self.current().kind != .Eof) {
            // Parse key (must be string or identifier)
            const key = try self.parseExpression();
            _ = try self.expect(.Colon);
            const value = try self.parseExpression();
            
            try dict.LiteralDict.keys.append(key);
            try dict.LiteralDict.values.append(value);
            
            if (!self.match(.Comma)) break;
        }

        _ = try self.expect(.RightBrace);
        return dict;
    }
};
