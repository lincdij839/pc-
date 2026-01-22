// PC Language Lexer - 完整實作
const std = @import("std");
const token = @import("token.zig");
const Token = token.Token;
const TokenKind = token.TokenKind;

pub const LexerError = error{
    UnexpectedChar,
    UnterminatedString,
    InvalidNumber,
    OutOfMemory,
};

pub const Lexer = struct {
    source: []const u8,
    pos: usize,
    line: usize,
    column: usize,
    allocator: std.mem.Allocator,
    indent_stack: std.ArrayList(usize),  // 縮進棧
    at_line_start: bool,                 // 是否在行首
    pending_dedents: usize,              // 待處理的 DEDENT 數量

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Lexer {
        var indent_stack = std.ArrayList(usize).init(allocator);
        indent_stack.append(0) catch {}; // 初始縮進為 0
        return .{
            .source = source,
            .pos = 0,
            .line = 1,
            .column = 1,
            .allocator = allocator,
            .indent_stack = indent_stack,
            .at_line_start = true,
            .pending_dedents = 0,
        };
    }
    
    pub fn deinit(self: *Lexer) void {
        self.indent_stack.deinit();
    }

    fn current(self: *const Lexer) ?u8 {
        if (self.pos >= self.source.len) return null;
        return self.source[self.pos];
    }

    fn peek(self: *const Lexer, offset: usize) ?u8 {
        const pos = self.pos + offset;
        if (pos >= self.source.len) return null;
        return self.source[pos];
    }

    fn advance(self: *Lexer) void {
        if (self.pos < self.source.len) {
            if (self.source[self.pos] == '\n') {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.pos += 1;
        }
    }

    fn skipWhitespace(self: *Lexer) void {
        while (self.current()) |c| {
            if (c == ' ' or c == '\t' or c == '\r') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skipComment(self: *Lexer) void {
        // Skip until end of line
        while (self.current()) |c| {
            if (c == '\n') break;
            self.advance();
        }
    }

    fn scanIdentifier(self: *Lexer) []const u8 {
        const start = self.pos;
        while (self.current()) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }
        return self.source[start..self.pos];
    }

    fn scanNumber(self: *Lexer) !Token {
        const start_line = self.line;
        const start_col = self.column;
        const start = self.pos;
        var is_float = false;

        // Check for hexadecimal (0x), octal (0o), binary (0b)
        if (self.current() == '0' and self.peek(1) != null) {
            const next = self.peek(1).?;
            if (next == 'x' or next == 'X') {
                // Hexadecimal
                self.advance(); // skip '0'
                self.advance(); // skip 'x'
                while (self.current()) |c| {
                    if (std.ascii.isHex(c) or c == '_') {
                        self.advance();
                    } else {
                        break;
                    }
                }
                const lexeme = self.source[start..self.pos];
                return Token{
                    .kind = .Integer,
                    .lexeme = lexeme,
                    .line = start_line,
                    .column = start_col,
                };
            } else if (next == 'o' or next == 'O') {
                // Octal
                self.advance(); // skip '0'
                self.advance(); // skip 'o'
                while (self.current()) |c| {
                    if (c >= '0' and c <= '7' or c == '_') {
                        self.advance();
                    } else {
                        break;
                    }
                }
                const lexeme = self.source[start..self.pos];
                return Token{
                    .kind = .Integer,
                    .lexeme = lexeme,
                    .line = start_line,
                    .column = start_col,
                };
            } else if (next == 'b' or next == 'B') {
                // Binary
                self.advance(); // skip '0'
                self.advance(); // skip 'b'
                while (self.current()) |c| {
                    if (c == '0' or c == '1' or c == '_') {
                        self.advance();
                    } else {
                        break;
                    }
                }
                const lexeme = self.source[start..self.pos];
                return Token{
                    .kind = .Integer,
                    .lexeme = lexeme,
                    .line = start_line,
                    .column = start_col,
                };
            }
        }

        // Scan decimal digits
        while (self.current()) |c| {
            if (std.ascii.isDigit(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }

        // Check for decimal point
        if (self.current() == '.' and self.peek(1) != null and std.ascii.isDigit(self.peek(1).?)) {
            is_float = true;
            self.advance(); // Skip '.'

            while (self.current()) |c| {
                if (std.ascii.isDigit(c) or c == '_') {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        // Check for exponent
        if (self.current()) |c| {
            if (c == 'e' or c == 'E') {
                is_float = true;
                self.advance();

                if (self.current()) |next| {
                    if (next == '+' or next == '-') {
                        self.advance();
                    }
                }

                while (self.current()) |digit| {
                    if (std.ascii.isDigit(digit)) {
                        self.advance();
                    } else {
                        break;
                    }
                }
            }
        }

        const lexeme = self.source[start..self.pos];
        return Token{
            .kind = if (is_float) .Float else .Integer,
            .lexeme = lexeme,
            .line = start_line,
            .column = start_col,
        };
    }

    fn scanString(self: *Lexer) !Token {
        const start_line = self.line;
        const start_col = self.column;
        const quote = self.current().?;
        self.advance(); // Skip opening quote

        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        while (self.current()) |c| {
            if (c == quote) {
                self.advance(); // Skip closing quote
                const lexeme = try result.toOwnedSlice();
                return Token{
                    .kind = .String,
                    .lexeme = lexeme,
                    .line = start_line,
                    .column = start_col,
                };
            }

            if (c == '\\') {
                self.advance();
                const escaped = self.current() orelse return LexerError.UnterminatedString;
                const char = switch (escaped) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    '"' => '"',
                    '\'' => '\'',
                    else => escaped,
                };
                try result.append(char);
                self.advance();
            } else {
                try result.append(c);
                self.advance();
            }
        }

        return LexerError.UnterminatedString;
    }

    pub fn nextToken(self: *Lexer) !Token {
        self.skipWhitespace();

        if (self.current() == null) {
            return Token{
                .kind = .Eof,
                .lexeme = "",
                .line = self.line,
                .column = self.column,
            };
        }

        const c = self.current().?;
        const start_line = self.line;
        const start_col = self.column;

        // Comments
        if (c == '#') {
            self.skipComment();
            return self.nextToken();
        }

        // Newline
        if (c == '\n') {
            self.advance();
            return Token{
                .kind = .Newline,
                .lexeme = "\n",
                .line = start_line,
                .column = start_col,
            };
        }

        // Identifiers and keywords
        if (std.ascii.isAlphabetic(c) or c == '_') {
            const lexeme = self.scanIdentifier();
            return Token{
                .kind = token.keywordOrIdentifier(lexeme),
                .lexeme = lexeme,
                .line = start_line,
                .column = start_col,
            };
        }

        // Numbers
        if (std.ascii.isDigit(c)) {
            return try self.scanNumber();
        }

        // Strings
        if (c == '"' or c == '\'') {
            return try self.scanString();
        }

        // Two-character operators
        if (c == '=' and self.peek(1) == '=') {
            self.advance();
            self.advance();
            return Token{ .kind = .EqualEqual, .lexeme = "==", .line = start_line, .column = start_col };
        }
        if (c == '!' and self.peek(1) == '=') {
            self.advance();
            self.advance();
            return Token{ .kind = .NotEqual, .lexeme = "!=", .line = start_line, .column = start_col };
        }
        if (c == '<' and self.peek(1) == '=') {
            self.advance();
            self.advance();
            return Token{ .kind = .LessEqual, .lexeme = "<=", .line = start_line, .column = start_col };
        }
        if (c == '<' and self.peek(1) == '<') {
            self.advance();
            self.advance();
            return Token{ .kind = .LeftShift, .lexeme = "<<", .line = start_line, .column = start_col };
        }
        if (c == '>' and self.peek(1) == '=') {
            self.advance();
            self.advance();
            return Token{ .kind = .GreaterEqual, .lexeme = ">=", .line = start_line, .column = start_col };
        }
        if (c == '>' and self.peek(1) == '>') {
            self.advance();
            self.advance();
            return Token{ .kind = .RightShift, .lexeme = ">>", .line = start_line, .column = start_col };
        }
        if (c == '-' and self.peek(1) == '>') {
            self.advance();
            self.advance();
            return Token{ .kind = .Arrow, .lexeme = "->", .line = start_line, .column = start_col };
        }
        if (c == '=' and self.peek(1) == '>') {
            self.advance();
            self.advance();
            return Token{ .kind = .FatArrow, .lexeme = "=>", .line = start_line, .column = start_col };
        }
        if (c == '*' and self.peek(1) == '*') {
            self.advance();
            self.advance();
            return Token{ .kind = .Power, .lexeme = "**", .line = start_line, .column = start_col };
        }

        // Single-character tokens
        const single_char = switch (c) {
            '+' => TokenKind.Plus,
            '-' => TokenKind.Minus,
            '*' => TokenKind.Star,
            '/' => TokenKind.Slash,
            '%' => TokenKind.Percent,
            '=' => TokenKind.Equal,
            '<' => TokenKind.Less,
            '>' => TokenKind.Greater,
            '&' => TokenKind.Ampersand,
            '|' => TokenKind.Pipe,
            '^' => TokenKind.Caret,
            '~' => TokenKind.Tilde,
            '(' => TokenKind.LeftParen,
            ')' => TokenKind.RightParen,
            '[' => TokenKind.LeftBracket,
            ']' => TokenKind.RightBracket,
            '{' => TokenKind.LeftBrace,
            '}' => TokenKind.RightBrace,
            ',' => TokenKind.Comma,
            ':' => TokenKind.Colon,
            ';' => TokenKind.Semicolon,
            '.' => TokenKind.Dot,
            '@' => TokenKind.At,
            else => {
                std.debug.print("Unexpected character: '{c}' (0x{x})\n", .{ c, c });
                return LexerError.UnexpectedChar;
            },
        };

        self.advance();
        const lexeme = self.source[start_col - 1 .. self.pos];
        return Token{
            .kind = single_char,
            .lexeme = lexeme,
            .line = start_line,
            .column = start_col,
        };
    }

    pub fn scanAll(self: *Lexer) !std.ArrayList(Token) {
        var tokens = std.ArrayList(Token).init(self.allocator);
        errdefer tokens.deinit();

        while (true) {
            const tok = try self.nextToken();
            try tokens.append(tok);
            if (tok.kind == .Eof) break;
        }

        return tokens;
    }
};
