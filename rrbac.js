/**
 * @fileoverview A Proof of Concept for the Resource and Role Hierarchy Based Access Control (RRBAC) model.
 * This implementation is based on the paper "Resource and Role Hierarchy Based Access Control for Resourceful Systems"
 * by Solanki, Huang, Yen, and Bastani (COMPSAC 2018).
 * This version is updated to include the concept of "actions" (access rights) as part of a permission.
 */

// --- Data Structures ---

/**
 * Represents a Resource node in the resource hierarchy (tree).
 * Corresponds to 'd' in the paper.
 */
export class Resource {
  /**
   * @param {string} id - A unique identifier for the resource.
   */
  constructor(id) {
    this.id = id;
    this.parent = null;
    this.children = [];

    // --- RRBAC Specific Attributes ---

    /**
     * @property {Map<string, Set<Role>>} rwp - "roles with permission". Maps an action (e.g., 'read', 'write')
     * to a Set of Roles that have been explicitly assigned that permission for this resource.
     */
    this.rwp = new Map();

    /**
     * @property {Map<string, Set<Role>>} erwp - "expanded roles with permission". Includes roles from rwp
     * and propagated roles, also mapped by action.
     */
    this.erwp = new Map();

    /**
     * @property {Resource|null} acpn - "access control parent node". Points to the closest ancestor with any assigned permissions.
     */
    this.acpn = null;

    /**
     * @property {Set<Resource>} accn - "access control children nodes". Points to the closest descendants with any assigned permissions.
     */
    this.accn = new Set();
  }

  /**
   * Adds a child resource to this node.
   * @param {Resource} childNode - The child resource node.
   */
  addChild(childNode) {
    childNode.parent = this;
    this.children.push(childNode);
  }

  /**
   * Traverses the subtree starting from this node.
   * @param {function(Resource): void} callback - A function to call for each node in the subtree.
   */
  traverseSubtree(callback) {
    const queue = [this];
    while (queue.length > 0) {
      const currentNode = queue.shift();
      callback(currentNode);
      for (const child of currentNode.children) {
        queue.push(child);
      }
    }
  }
}

/**
 * Represents a Role in the role hierarchy.
 * Corresponds to 'r' in the paper.
 */
export class Role {
  /**
   * @param {string} id - A unique identifier for the role.
   */
  constructor(id) {
    this.id = id;
    this.parents = new Set(); // A role can have multiple senior roles
    this.children = new Set(); // A role can have multiple junior roles
  }

  /**
   * Adds a parent role (a more senior role).
   * @param {Role} parentRole - The parent role.
   */
  addParent(parentRole) {
    this.parents.add(parentRole);
    parentRole.children.add(this);
  }

  /**
   * Gets all ancestor roles in the hierarchy.
   * @returns {Set<Role>} A set of all ancestor roles.
   */
  getAncestors() {
    const ancestors = new Set();
    const queue = [...this.parents];
    while (queue.length > 0) {
      const current = queue.shift();
      if (!ancestors.has(current)) {
        ancestors.add(current);
        for (const parent of current.parents) {
          queue.push(parent);
        }
      }
    }
    return ancestors;
  }
}

// --- Core RRBAC Logic ---

export class RRBACSystem {
  /**
   * @param {Resource} resourceRoot - The root of the resource tree.
   * @param {Map<string, Role>} roles - A map of all roles in the system.
   */
  constructor(resourceRoot, roles) {
    this.resourceRoot = resourceRoot;
    this.roles = roles;
  }

  /**
   * Implements the permission_assignment algorithm from Section 4.2 of the paper.
   * Assigns permission for a resource and a specific action to a role.
   * @param {Resource} resourceNode - The resource to assign permission for (dy in the paper).
   * @param {Role} role - The role to grant permission to (ri in the paper).
   * @param {string} action - The access right, e.g., 'read', 'write'.
   */
  permissionAssignment(resourceNode, role, action) {
    console.log(
      `\n--- Assigning [${action}] permission for resource '${resourceNode.id}' to role '${role.id}' ---`
    );

    const rolesForAction = resourceNode.rwp.get(action) || new Set();
    if (rolesForAction.has(role)) {
      console.log("Permission already exists. No action taken.");
      return;
    }

    // The acpn/accn logic is triggered if this is the FIRST permission of ANY kind assigned to this node.
    const wasEmpty = resourceNode.rwp.size === 0;

    if (wasEmpty) {
      const originalAcpn = resourceNode.acpn;
      resourceNode.acpn = null;

      if (originalAcpn) {
        // This node is no longer just inheriting, so it needs to be in its parent's accn list.
        // The paper's logic for removing descendants from the originalAcpn's accn is complex.
        // For this PoC, we ensure the current node is correctly linked.
        originalAcpn.accn.add(resourceNode);
      }

      // Descendants that pointed to our old acpn should now point to us.
      for (const child of resourceNode.children) {
        child.traverseSubtree((node) => {
          if (node.acpn === originalAcpn) {
            node.acpn = resourceNode;
          }
        });
      }
    }

    // Add the explicit permission
    if (!resourceNode.rwp.has(action)) {
      resourceNode.rwp.set(action, new Set());
    }
    resourceNode.rwp.get(action).add(role);

    // Calculate all roles that get this permission due to role hierarchy
    const newRwp = new Set([role]);
    const ancestors = role.getAncestors();
    for (const ancestor of ancestors) {
      newRwp.add(ancestor);
    }

    // Propagate the new permissions down the resource tree
    this.propagateRwp(resourceNode, newRwp, action);
    console.log(`Assignment complete.`);
  }

  /**
   * Implements the propagate_rwp helper function.
   * Recursively propagates roles for a specific action down the accn links.
   * @param {Resource} resourceNode - The current resource node (d in the paper).
   * @param {Set<Role>} newRwp - The set of new roles to propagate.
   * @param {string} action - The action being propagated.
   */
  propagateRwp(resourceNode, newRwp, action) {
    if (!resourceNode.erwp.has(action)) {
      resourceNode.erwp.set(action, new Set());
    }
    const erwpForAction = resourceNode.erwp.get(action);
    const originalErwpSize = erwpForAction.size;

    for (const role of newRwp) {
      erwpForAction.add(role);
    }

    if (erwpForAction.size > originalErwpSize) {
      for (const childWithPermission of resourceNode.accn) {
        this.propagateRwp(childWithPermission, newRwp, action);
      }
    }
  }

  /**
   * Checks if a role has permission to perform an action on a resource.
   * This is the validation step.
   * @param {Role} role - The role requesting access.
   * @param {Resource} resource - The resource being accessed.
   * @param {string} action - The action being requested.
   * @returns {boolean} - True if access is granted, false otherwise.
   */
  canAccess(role, resource, action) {
    let currentNode = resource;
    while (currentNode) {
      if (currentNode.erwp.get(action)?.has(role)) {
        return true;
      }
      // Traverse up the access control parent chain
      currentNode = currentNode.acpn;
    }
    return false;
  }

  /**
   * A utility to print the state of the resource tree for visualization.
   */
  printResourceTreeState() {
    console.log("\n--- Current Resource Tree State ---");
    const printMap = (map) => {
      if (map.size === 0) return "none";
      let result = "";
      for (const [action, roles] of map.entries()) {
        result += `\n    [${action}]: {${[...roles]
          .map((r) => r.id)
          .join(", ")}}`;
      }
      return result;
    };
    const printNode = (node, indent = "") => {
      const rwp = printMap(node.rwp);
      const erwp = printMap(node.erwp);
      const acpn = node.acpn ? node.acpn.id : "null";
      const accn = [...node.accn].map((n) => n.id).join(", ") || "none";
      console.log(`${indent}* ${node.id}:`);
      console.log(`${indent}  - RWP: ${rwp}`);
      console.log(`${indent}  - ERWP: ${erwp}`);
      console.log(`${indent}  - ACPN: -> ${acpn}`);
      console.log(`${indent}  - ACCN: -> {${accn}}`);
      node.children.forEach((child) => printNode(child, indent + "  "));
    };
    printNode(this.resourceRoot);
  }
}
