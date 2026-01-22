// PC Language Compiler - Main Entry Point
const std = @import("std");
const Lexer = @import("lexer.zig").Lexer;
const Parser = @import("parser.zig").Parser;
const Interpreter = @import("interpreter.zig").Interpreter;
const Codegen = @import("codegen.zig").Codegen;
const Token = @import("token.zig").Token;
const ast = @import("ast.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};  
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // HolyC style: if only 2 args, directly run the file
    if (args.len == 2) {
        try runFile(allocator, args[1]);
        return;
    }

    if (args.len < 3) {
        try printUsage();
        return;
    }

    const command = args[1];
    const filename = args[2];

    if (std.mem.eql(u8, command, "lex")) {
        try lexFile(allocator, filename);
    } else if (std.mem.eql(u8, command, "parse")) {
        try parseFile(allocator, filename);
    } else if (std.mem.eql(u8, command, "run")) {
        try runFile(allocator, filename);
    } else if (std.mem.eql(u8, command, "compile")) {
        try compileFile(allocator, filename);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        try printUsage();
    }
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\PC Language Compiler v0.1.0 (Zig Implementation)
        \\Usage: 
        \\  pc <file>              - Run the program (HolyC style)
        \\  pc [command] <file>    - Execute specific command
        \\
        \\Commands:
        \\  lex       - Tokenize the source file
        \\  parse     - Parse and show AST
        \\  run       - Run the program (interpreter mode)
        \\  compile   - Compile to executable
        \\
        \\Examples:
        \\  pc hello.pc            - Direct execution (like HolyC)
        \\  pc lex example.pc      - Show tokens
        \\  pc run hello.pc        - Run program
        \\  pc compile program.pc  - Compile to binary
        \\
    , .{});
}

fn lexFile(allocator: std.mem.Allocator, filename: []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Lexing file: {s}\n", .{filename});

    // Read file
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024); // 10MB max
    defer allocator.free(source);

    // Tokenize
    var lexer = Lexer.init(allocator, source);
    const tokens = try lexer.scanAll();
    defer tokens.deinit();

    try stdout.print("Tokens found: {}\n", .{tokens.items.len});
    for (tokens.items) |tok| {
        try stdout.print("  {}\n", .{tok});
    }
}

fn parseFile(allocator: std.mem.Allocator, filename: []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Parsing file: {s}\n", .{filename});

    // Read file
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    // Tokenize
    var lexer = Lexer.init(allocator, source);
    const tokens = try lexer.scanAll();
    defer tokens.deinit();

    try stdout.print("Tokens: {}\n", .{tokens.items.len});

    // Parse
    var parser = Parser.init(allocator, tokens.items);
    const prog_ast = try parser.parseProgram();
    defer ast.freeNode(allocator, prog_ast);

    try stdout.print("Parsing complete!\n", .{});
}

fn runFile(allocator: std.mem.Allocator, filename: []const u8) !void {
    // Read file
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    // Tokenize
    var lexer = Lexer.init(allocator, source);
    const tokens = try lexer.scanAll();
    defer tokens.deinit();

    // Parse
    var parser = Parser.init(allocator, tokens.items);
    const prog_ast = try parser.parseProgram();
    defer ast.freeNode(allocator, prog_ast);

    // Execute (HolyC style - no extra output)
    var interp = Interpreter.init(allocator);
    defer interp.deinit();
    
    try interp.execute(prog_ast);
}

fn compileFile(allocator: std.mem.Allocator, filename: []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Compiling file: {s}\n", .{filename});

    // Read file
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    // Tokenize
    var lexer = Lexer.init(allocator, source);
    const tokens = try lexer.scanAll();
    defer tokens.deinit();

    // Parse
    var parser = Parser.init(allocator, tokens.items);
    const prog_ast = try parser.parseProgram();
    defer ast.freeNode(allocator, prog_ast);

    // Generate LLVM IR
    var codegen = try Codegen.init(allocator, "main");
    defer codegen.deinit();
    
    try codegen.generate(prog_ast);
    
    // Emit IR file
    const ir_file = try std.fmt.allocPrint(allocator, "{s}.ll", .{filename});
    defer allocator.free(ir_file);
    try codegen.emitIR(ir_file);
    
    // Emit object file
    const obj_file = try std.fmt.allocPrint(allocator, "{s}.o", .{filename});
    defer allocator.free(obj_file);
    try codegen.emitObject(obj_file);
    
    // Link to executable
    const exe_file = try std.fmt.allocPrint(allocator, "{s}.exe", .{filename});
    defer allocator.free(exe_file);
    try Codegen.link(allocator, obj_file, exe_file);
    
    try stdout.print("[✓] Compilation complete: {s}\n", .{exe_file});
}

test "basic lexer test" {
    const allocator = std.testing.allocator;
    const source = "def main(): return 42";

    var lexer = Lexer.init(allocator, source);
    const tokens = try lexer.scanAll();
    defer tokens.deinit();

    try std.testing.expect(tokens.items.len > 0);
}
