// PC Language Abstract Syntax Tree
const std = @import("std");

pub const NodeKind = enum {
    Program,
    FunctionDef,
    ClassDef,
    StructDef,
    VariableDecl,
    Assignment,
    IfStatement,
    WhileLoop,
    ForLoop,
    ReturnStatement,
    BinaryOp,
    UnaryOp,
    FunctionCall,
    Identifier,
    LiteralInt,
    LiteralFloat,
    LiteralString,
    LiteralBool,
    LiteralList,
    LiteralDict,
    IndexAccess,
    Block,
};

pub const Node = union(NodeKind) {
    Program: struct {
        statements: std.ArrayList(*Node),
    },
    FunctionDef: struct {
        name: []const u8,
        params: std.ArrayList(*Node),
        return_type: ?*Node,
        body: *Node,
    },
    ClassDef: struct {
        name: []const u8,
        methods: std.ArrayList(*Node),
    },
    StructDef: struct {
        name: []const u8,
        fields: std.ArrayList(*Node),
    },
    VariableDecl: struct {
        name: []const u8,
        type_annotation: ?*Node,
        initializer: ?*Node,
    },
    Assignment: struct {
        target: *Node,
        value: *Node,
    },
    IfStatement: struct {
        condition: *Node,
        then_branch: *Node,
        else_branch: ?*Node,
    },
    WhileLoop: struct {
        condition: *Node,
        body: *Node,
    },
    ForLoop: struct {
        iterator: *Node,
        iterable: *Node,
        body: *Node,
    },
    ReturnStatement: struct {
        value: ?*Node,
    },
    BinaryOp: struct {
        operator: []const u8,
        left: *Node,
        right: *Node,
    },
    UnaryOp: struct {
        operator: []const u8,
        operand: *Node,
    },
    FunctionCall: struct {
        callee: *Node,
        arguments: std.ArrayList(*Node),
    },
    Identifier: struct {
        name: []const u8,
    },
    LiteralInt: struct {
        value: i64,
    },
    LiteralFloat: struct {
        value: f64,
    },
    LiteralString: struct {
        value: []const u8,
    },
    LiteralBool: struct {
        value: bool,
    },
    LiteralList: struct {
        elements: std.ArrayList(*Node),
    },
    LiteralDict: struct {
        keys: std.ArrayList(*Node),
        values: std.ArrayList(*Node),
    },
    IndexAccess: struct {
        object: *Node,
        index: *Node,
    },
    Block: struct {
        statements: std.ArrayList(*Node),
    },
};

pub fn createNode(allocator: std.mem.Allocator, kind: NodeKind) !*Node {
    const node = try allocator.create(Node);
    node.* = switch (kind) {
        .Program => Node{ .Program = .{ .statements = std.ArrayList(*Node).init(allocator) } },
        .Block => Node{ .Block = .{ .statements = std.ArrayList(*Node).init(allocator) } },
        .LiteralList => Node{ .LiteralList = .{ .elements = std.ArrayList(*Node).init(allocator) } },
        .LiteralDict => Node{ .LiteralDict = .{ 
            .keys = std.ArrayList(*Node).init(allocator),
            .values = std.ArrayList(*Node).init(allocator),
        } },
        else => @panic("Use specific create functions for this node type"),
    };
    return node;
}

pub fn createIdentifier(allocator: std.mem.Allocator, name: []const u8) !*Node {
    const node = try allocator.create(Node);
    node.* = Node{ .Identifier = .{ .name = name } };
    return node;
}

pub fn createInt(allocator: std.mem.Allocator, value: i64) !*Node {
    const node = try allocator.create(Node);
    node.* = Node{ .LiteralInt = .{ .value = value } };
    return node;
}

pub fn createBinaryOp(allocator: std.mem.Allocator, operator: []const u8, left: *Node, right: *Node) !*Node {
    const node = try allocator.create(Node);
    node.* = Node{ .BinaryOp = .{ .operator = operator, .left = left, .right = right } };
    return node;
}

pub fn createFunctionCall(allocator: std.mem.Allocator, callee: *Node) !*Node {
    const node = try allocator.create(Node);
    node.* = Node{ .FunctionCall = .{
        .callee = callee,
        .arguments = std.ArrayList(*Node).init(allocator),
    } };
    return node;
}

// Free AST node recursively
pub fn freeNode(allocator: std.mem.Allocator, node: *Node) void {
    switch (node.*) {
        .Program => |v| {
            for (v.statements.items) |stmt| {
                freeNode(allocator, stmt);
            }
            v.statements.deinit();
        },
        .FunctionDef => |v| {
            for (v.params.items) |param| {
                freeNode(allocator, param);
            }
            v.params.deinit();
            if (v.return_type) |rt| freeNode(allocator, rt);
            freeNode(allocator, v.body);
        },
        .ClassDef => |v| {
            for (v.methods.items) |method| {
                freeNode(allocator, method);
            }
            v.methods.deinit();
        },
        .StructDef => |v| {
            for (v.fields.items) |field| {
                freeNode(allocator, field);
            }
            v.fields.deinit();
        },
        .VariableDecl => |v| {
            if (v.type_annotation) |ta| freeNode(allocator, ta);
            if (v.initializer) |init| freeNode(allocator, init);
        },
        .Assignment => |v| {
            freeNode(allocator, v.target);
            freeNode(allocator, v.value);
        },
        .IfStatement => |v| {
            freeNode(allocator, v.condition);
            freeNode(allocator, v.then_branch);
            if (v.else_branch) |eb| freeNode(allocator, eb);
        },
        .WhileLoop => |v| {
            freeNode(allocator, v.condition);
            freeNode(allocator, v.body);
        },
        .ForLoop => |v| {
            freeNode(allocator, v.iterator);
            freeNode(allocator, v.iterable);
            freeNode(allocator, v.body);
        },
        .ReturnStatement => |v| {
            if (v.value) |val| freeNode(allocator, val);
        },
        .BinaryOp => |v| {
            freeNode(allocator, v.left);
            freeNode(allocator, v.right);
        },
        .UnaryOp => |v| {
            freeNode(allocator, v.operand);
        },
        .FunctionCall => |v| {
            freeNode(allocator, v.callee);
            for (v.arguments.items) |arg| {
                freeNode(allocator, arg);
            }
            v.arguments.deinit();
        },
        .LiteralList => |v| {
            for (v.elements.items) |elem| {
                freeNode(allocator, elem);
            }
            v.elements.deinit();
        },
        .LiteralDict => |v| {
            for (v.keys.items) |key| {
                freeNode(allocator, key);
            }
            for (v.values.items) |val| {
                freeNode(allocator, val);
            }
            v.keys.deinit();
            v.values.deinit();
        },
        .IndexAccess => |v| {
            freeNode(allocator, v.object);
            freeNode(allocator, v.index);
        },
        .Block => |v| {
            for (v.statements.items) |stmt| {
                freeNode(allocator, stmt);
            }
            v.statements.deinit();
        },
        // Leaf nodes - no children to free
        .Identifier, .LiteralInt, .LiteralFloat, .LiteralString, .LiteralBool => {},
    }
    allocator.destroy(node);
}
