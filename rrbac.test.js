// rrbac.spec.js
// Tests for rrbac.js using Node.js test API
import assert from "node:assert/strict";
import { it, describe } from "node:test";
import { Resource, Role, RRBACSystem } from "./rrbac.js";

// Helper to create a simple resource tree and role hierarchy
describe("RRBAC", () => {
  it("basic permission assignment and access", () => {
    // Resources: root -> child1 -> child2
    const root = new Resource("root");
    const child1 = new Resource("child1");
    const child2 = new Resource("child2");
    root.addChild(child1);
    child1.addChild(child2);

    // Roles: admin > user
    const admin = new Role("admin");
    const user = new Role("user");
    user.addParent(admin); // admin is senior to user

    const roles = new Map([
      ["admin", admin],
      ["user", user],
    ]);

    const rrbac = new RRBACSystem(root, roles);

    // Assign 'read' permission to user on child1
    rrbac.permissionAssignment(child1, user, "read");

    // user and admin should have 'read' on child1 and its descendants
    assert(rrbac.canAccess(user, child1, "read"));
    assert(rrbac.canAccess(admin, child1, "read"));
    assert(rrbac.canAccess(user, child2, "read"));
    assert(rrbac.canAccess(admin, child2, "read"));
    // No access on root
    assert(!rrbac.canAccess(user, root, "read"));
    assert(!rrbac.canAccess(admin, root, "read"));
  });

  it("RRBAC denies access if no permission assigned", () => {
    const root = new Resource("root");
    const role = new Role("role");
    const roles = new Map([["role", role]]);
    const rrbac = new RRBACSystem(root, roles);
    assert(!rrbac.canAccess(role, root, "read"));
  });

  it("RRBAC permission propagation with multiple actions", () => {
    const root = new Resource("root");
    const file = new Resource("file");
    root.addChild(file);
    const editor = new Role("editor");
    const viewer = new Role("viewer");
    viewer.addParent(editor);
    const roles = new Map([
      ["editor", editor],
      ["viewer", viewer],
    ]);
    const rrbac = new RRBACSystem(root, roles);
    rrbac.permissionAssignment(file, editor, "write");
    rrbac.permissionAssignment(file, viewer, "read");
    assert(rrbac.canAccess(editor, file, "write"));
    assert(!rrbac.canAccess(viewer, file, "write"));
    assert(rrbac.canAccess(viewer, file, "read"));
    assert(rrbac.canAccess(editor, file, "read"));
  });

  it("RRBAC: deeply nested resource inheritance", () => {
    const root = new Resource("root");
    let parent = root;
    // Create a deep tree: root -> a -> b -> c -> d
    const nodes = ["a", "b", "c", "d"].map((id) => {
      const node = new Resource(id);
      parent.addChild(node);
      parent = node;
      return node;
    });
    const [a, b, c, d] = nodes;
    const role = new Role("role");
    const roles = new Map([["role", role]]);
    const rrbac = new RRBACSystem(root, roles);
    // Assign permission at 'b', should propagate to c and d
    rrbac.permissionAssignment(b, role, "read");
    assert(!rrbac.canAccess(role, root, "read"));
    assert(!rrbac.canAccess(role, a, "read"));
    assert(rrbac.canAccess(role, b, "read"));
    assert(rrbac.canAccess(role, c, "read"));
    assert(rrbac.canAccess(role, d, "read"));
  });

  it("RRBAC: multiple roles, overlapping permissions", () => {
    const root = new Resource("root");
    const doc = new Resource("doc");
    root.addChild(doc);
    const admin = new Role("admin");
    const editor = new Role("editor");
    const viewer = new Role("viewer");
    editor.addParent(admin);
    viewer.addParent(editor);
    const roles = new Map([
      ["admin", admin],
      ["editor", editor],
      ["viewer", viewer],
    ]);
    const rrbac = new RRBACSystem(root, roles);
    rrbac.permissionAssignment(doc, viewer, "read");
    rrbac.permissionAssignment(doc, editor, "write");
    assert(rrbac.canAccess(viewer, doc, "read"));
    assert(!rrbac.canAccess(viewer, doc, "write"));
    assert(rrbac.canAccess(editor, doc, "read"));
    assert(rrbac.canAccess(editor, doc, "write"));
    assert(rrbac.canAccess(admin, doc, "read"));
    assert(rrbac.canAccess(admin, doc, "write"));
  });

  it("RRBAC: circular role hierarchy does not cause infinite loop", () => {
    const root = new Resource("root");
    const roleA = new Role("A");
    const roleB = new Role("B");
    roleA.addParent(roleB);
    roleB.addParent(roleA); // circular
    const roles = new Map([
      ["A", roleA],
      ["B", roleB],
    ]);
    const rrbac = new RRBACSystem(root, roles);
    rrbac.permissionAssignment(root, roleA, "read");
    assert(rrbac.canAccess(roleA, root, "read"));
    assert(rrbac.canAccess(roleB, root, "read"));
  });

  it("RRBAC: assigning same permission twice is idempotent", () => {
    const root = new Resource("root");
    const role = new Role("role");
    const roles = new Map([["role", role]]);
    const rrbac = new RRBACSystem(root, roles);
    rrbac.permissionAssignment(root, role, "read");
    rrbac.permissionAssignment(root, role, "read"); // should not throw or duplicate
    assert(rrbac.canAccess(role, root, "read"));
  });

  it("RRBAC: no access for unrelated action", () => {
    const root = new Resource("root");
    const role = new Role("role");
    const roles = new Map([["role", role]]);
    const rrbac = new RRBACSystem(root, roles);
    rrbac.permissionAssignment(root, role, "read");
    assert(!rrbac.canAccess(role, root, "write"));
  });
});
