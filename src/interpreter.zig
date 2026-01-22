// PC Language Interpreter - Tree-walking interpreter (Refactored)
const std = @import("std");
const ast = @import("ast.zig");
const Node = ast.Node;
const builtins = @import("stdlib/builtins.zig");

pub const Value = union(enum) {
    Int: i64,
    Float: f64,
    String: []const u8,
    Bool: bool,
    None,
    List: std.ArrayList(Value),
    Dict: std.StringHashMap(Value),
    Function: struct {
        params: std.ArrayList(*Node),
        body: *Node,
    },
    Process: *anyopaque,  // Process handle (opaque pointer)
    Socket: *anyopaque,   // Network socket (opaque pointer)

    pub fn format(
        self: Value,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .Int => |v| try writer.print("{}", .{v}),
            .Float => |v| try writer.print("{d}", .{v}),
            .String => |v| try writer.print("{s}", .{v}),
            .Bool => |v| try writer.print("{}", .{v}),
            .None => try writer.print("None", .{}),
            .List => try writer.print("<list>", .{}),
            .Dict => try writer.print("<dict>", .{}),
            .Function => try writer.print("<function>", .{}),
            .Process => try writer.print("<process>", .{}),
            .Socket => try writer.print("<socket>", .{}),
        }
    }
};

pub const InterpreterError = error{
    UndefinedVariable,
    TypeError,
    RuntimeError,
    DivisionByZero,
    OutOfMemory,
} || std.fs.File.WriteError;

pub const Interpreter = struct {
    allocator: std.mem.Allocator,
    globals: std.StringHashMap(Value),
    scopes: std.ArrayList(std.StringHashMap(Value)),
    stdout: std.fs.File.Writer,
    return_flag: bool,
    return_value: Value,

    pub fn init(allocator: std.mem.Allocator) Interpreter {
        return .{
            .allocator = allocator,
            .globals = std.StringHashMap(Value).init(allocator),
            .scopes = std.ArrayList(std.StringHashMap(Value)).init(allocator),
            .stdout = std.io.getStdOut().writer(),
            .return_flag = false,
            .return_value = Value.None,
        };
    }

    pub fn deinit(self: *Interpreter) void {
        self.globals.deinit();
        for (self.scopes.items) |*scope| {
            scope.deinit();
        }
        self.scopes.deinit();
    }

    pub fn execute(self: *Interpreter, program: *Node) !void {
        if (program.* != .Program) {
            return InterpreterError.RuntimeError;
        }

        for (program.Program.statements.items) |stmt| {
            _ = try self.eval(stmt);
        }
    }

    pub fn eval(self: *Interpreter, node: *Node) InterpreterError!Value {
        return switch (node.*) {
            .LiteralInt => |v| Value{ .Int = v.value },
            .LiteralFloat => |v| Value{ .Float = v.value },
            .LiteralString => |v| Value{ .String = v.value },
            .LiteralBool => |v| Value{ .Bool = v.value },

            .LiteralList => |v| blk: {
                var list = std.ArrayList(Value).init(self.allocator);
                for (v.elements.items) |elem| {
                    try list.append(try self.eval(elem));
                }
                break :blk Value{ .List = list };
            },

            .LiteralDict => |v| blk: {
                var dict = std.StringHashMap(Value).init(self.allocator);
                for (v.keys.items, v.values.items) |key_node, val_node| {
                    const key_val = try self.eval(key_node);
                    const val = try self.eval(val_node);
                    
                    // Convert key to string
                    const key_str = switch (key_val) {
                        .String => |s| s,
                        .Int => |i| try std.fmt.allocPrint(self.allocator, "{}", .{i}),
                        else => "unknown",
                    };
                    
                    try dict.put(key_str, val);
                }
                break :blk Value{ .Dict = dict };
            },

            .IndexAccess => |v| blk: {
                const obj = try self.eval(v.object);
                const idx = try self.eval(v.index);
                
                if (obj == .List and idx == .Int) {
                    const index = @as(usize, @intCast(idx.Int));
                    if (index < obj.List.items.len) {
                        break :blk obj.List.items[index];
                    }
                } else if (obj == .Dict) {
                    // Dict access by string key
                    const key_str = switch (idx) {
                        .String => |s| s,
                        .Int => |i| try std.fmt.allocPrint(self.allocator, "{}", .{i}),
                        else => "unknown",
                    };
                    
                    if (obj.Dict.get(key_str)) |value| {
                        break :blk value;
                    }
                }
                break :blk Value.None;
            },

            .Identifier => |v| blk: {
                // Lookup from innermost scope to outermost
                if (self.scopes.items.len > 0) {
                    var i: usize = self.scopes.items.len;
                    while (i > 0) {
                        i -= 1;
                        if (self.scopes.items[i].get(v.name)) |value| {
                            break :blk value;
                        }
                    }
                }
                // Finally check globals
                const value = self.globals.get(v.name) orelse {
                    std.debug.print("Undefined variable: {s}\n", .{v.name});
                    return InterpreterError.UndefinedVariable;
                };
                break :blk value;
            },

            .BinaryOp => |v| try self.evalBinaryOp(v.operator, v.left, v.right),

            .Assignment => |v| blk: {
                const value = try self.eval(v.value);
                
                if (v.target.* == .Identifier) {
                    // Normal variable assignment
                    if (self.scopes.items.len > 0) {
                        try self.scopes.items[self.scopes.items.len - 1].put(v.target.Identifier.name, value);
                    } else {
                        try self.globals.put(v.target.Identifier.name, value);
                    }
                } else if (v.target.* == .IndexAccess) {
                    // Index assignment: list[0] = value or dict["key"] = value
                    const index_access = v.target.IndexAccess;
                    const idx = try self.eval(index_access.index);
                    
                    // Get the actual object pointer from variable
                    if (index_access.object.* == .Identifier) {
                        const var_name = index_access.object.Identifier.name;
                        
                        // Try to get from globals (use getPtr to modify in place)
                        if (self.globals.getPtr(var_name)) |target_ptr| {
                            if (target_ptr.* == .List and idx == .Int) {
                                // List assignment
                                const index = @as(usize, @intCast(idx.Int));
                                if (index < target_ptr.List.items.len) {
                                    target_ptr.List.items[index] = value;
                                }
                            } else if (target_ptr.* == .Dict) {
                                // Dict assignment
                                const key_str = switch (idx) {
                                    .String => |s| s,
                                    .Int => |i| try std.fmt.allocPrint(self.allocator, "{}", .{i}),
                                    else => "unknown",
                                };
                                try target_ptr.Dict.put(key_str, value);
                            }
                        }
                    }
                }
                break :blk value;
            },

            .VariableDecl => |v| blk: {
                const value = if (v.initializer) |initializer| 
                    try self.eval(initializer)
                else 
                    Value.None;
                try self.globals.put(v.name, value);
                break :blk value;
            },

            .FunctionCall => |v| try self.evalFunctionCall(v.callee, v.arguments),

            .FunctionDef => |v| blk: {
                const func_value = Value{
                    .Function = .{
                        .params = v.params,
                        .body = v.body,
                    },
                };
                try self.globals.put(v.name, func_value);
                break :blk Value.None;
            },

            .ReturnStatement => |v| blk: {
                self.return_value = if (v.value) |val| 
                    try self.eval(val)
                else 
                    Value.None;
                self.return_flag = true;
                break :blk Value.None;
            },

            .IfStatement => |v| blk: {
                const condition = try self.eval(v.condition);
                const is_true = switch (condition) {
                    .Bool => |b| b,
                    .Int => |i| i != 0,
                    .None => false,
                    else => true,
                };

                if (is_true) {
                    _ = try self.eval(v.then_branch);
                } else if (v.else_branch) |else_branch| {
                    _ = try self.eval(else_branch);
                }
                break :blk Value.None;
            },

            .WhileLoop => |v| blk: {
                while (true) {
                    const condition = try self.eval(v.condition);
                    const is_true = switch (condition) {
                        .Bool => |b| b,
                        .Int => |i| i != 0,
                        else => false,
                    };
                    if (!is_true) break;
                    _ = try self.eval(v.body);
                }
                break :blk Value.None;
            },

            .ForLoop => |v| blk: {
                // Evaluate the iterable
                const iterable = try self.eval(v.iterable);
                
                // For now, support range-like iteration on integers
                if (iterable == .Int) {
                    const max = iterable.Int;
                    var i: i64 = 0;
                    while (i < max) : (i += 1) {
                        // Set iterator variable
                        if (v.iterator.* == .Identifier) {
                            try self.globals.put(v.iterator.Identifier.name, Value{ .Int = i });
                        }
                        _ = try self.eval(v.body);
                    }
                }
                break :blk Value.None;
            },

            .Block => |v| blk: {
                var result: Value = .None;
                for (v.statements.items) |stmt| {
                    result = try self.eval(stmt);
                    if (self.return_flag) break;
                }
                break :blk result;
            },

            else => {
                std.debug.print("Unimplemented node type: {s}\n", .{@tagName(node.*)});
                return Value.None;
            },
        };
    }

    fn evalBinaryOp(self: *Interpreter, operator: []const u8, left: *Node, right: *Node) !Value {
        const left_val = try self.eval(left);
        const right_val = try self.eval(right);

        // Debug output
        // std.debug.print("BinaryOp: {s} {s} {s}\n", .{@tagName(left_val), operator, @tagName(right_val)});

        // Integer operations
        if (left_val == .Int and right_val == .Int) {
            const l = left_val.Int;
            const r = right_val.Int;

            if (std.mem.eql(u8, operator, "+")) return Value{ .Int = l + r };
            if (std.mem.eql(u8, operator, "-")) return Value{ .Int = l - r };
            if (std.mem.eql(u8, operator, "*")) return Value{ .Int = l * r };
            if (std.mem.eql(u8, operator, "/")) {
                if (r == 0) return InterpreterError.DivisionByZero;
                return Value{ .Int = @divTrunc(l, r) };
            }
            if (std.mem.eql(u8, operator, "%")) return Value{ .Int = @mod(l, r) };
            if (std.mem.eql(u8, operator, "==")) return Value{ .Bool = l == r };
            if (std.mem.eql(u8, operator, "!=")) return Value{ .Bool = l != r };
            if (std.mem.eql(u8, operator, "<")) return Value{ .Bool = l < r };
            if (std.mem.eql(u8, operator, ">")) return Value{ .Bool = l > r };
            if (std.mem.eql(u8, operator, "<=")) return Value{ .Bool = l <= r };
            if (std.mem.eql(u8, operator, ">=")) return Value{ .Bool = l >= r };
        }

        // String operations
        if (left_val == .String and right_val == .String) {
            if (std.mem.eql(u8, operator, "+")) {
                const concat_result = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ left_val.String, right_val.String });
                return Value{ .String = concat_result };
            }
            if (std.mem.eql(u8, operator, "==")) {
                return Value{ .Bool = std.mem.eql(u8, left_val.String, right_val.String) };
            }
            if (std.mem.eql(u8, operator, "!=")) {
                return Value{ .Bool = !std.mem.eql(u8, left_val.String, right_val.String) };
            }
        }

        std.debug.print("Type error in binary operation: {s} {s} {s}\n", .{@tagName(left_val), operator, @tagName(right_val)});
        return InterpreterError.TypeError;
    }

    fn evalFunctionCall(self: *Interpreter, callee: *Node, arguments: std.ArrayList(*Node)) !Value {
        // Get function name
        if (callee.* != .Identifier) return Value.None;
        const name = callee.Identifier.name;

        // Evaluate all arguments first
        var eval_args = std.ArrayList(Value).init(self.allocator);
        defer eval_args.deinit();
        for (arguments.items) |arg| {
            try eval_args.append(try self.eval(arg));
        }

        // Check built-in functions
        if (builtins.builtins.get(name)) |builtin_fn| {
            return builtin_fn(self, eval_args.items);
        }

        // User-defined functions
        if (self.globals.get(name)) |func_val| {
            if (func_val == .Function) {
                return try self.callUserFunction(func_val.Function, eval_args.items);
            }
        }

        return Value.None;
    }

    fn callUserFunction(self: *Interpreter, func: anytype, args: []Value) !Value {
        // Push new scope
        var local_scope = std.StringHashMap(Value).init(self.allocator);
        try self.scopes.append(local_scope);
        defer {
            _ = self.scopes.pop();
            local_scope.deinit();
        }

        // Bind parameters to current scope
        for (func.params.items, 0..) |param, i| {
            if (param.* == .Identifier) {
                const arg_val = if (i < args.len) args[i] else Value.None;
                try self.scopes.items[self.scopes.items.len - 1].put(param.Identifier.name, arg_val);
            }
        }

        // Execute function body
        const prev_return_flag = self.return_flag;
        self.return_flag = false;
        
        _ = try self.eval(func.body);
        
        // Get return value and restore state
        const result = self.return_value;
        self.return_flag = prev_return_flag;
        
        return result;
    }

    pub fn registerBuiltin(self: *Interpreter, name: []const u8) !void {
        // Built-ins are handled directly in evalFunctionCall
        _ = self;
        _ = name;
    }
};
