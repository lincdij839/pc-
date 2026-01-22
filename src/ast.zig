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
