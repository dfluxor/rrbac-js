# RRBAC: Resource and Role Hierarchy Based Access Control for Node.js

A Node.js implementation of the Resource and Role Hierarchy Based Access Control (RRBAC) model, based on the paper by Solanki, Huang, Yen, and Bastani (COMPSAC 2018). This library supports hierarchical roles, hierarchical resources, and action-based permissions.

## Features

- Resource and role hierarchies
- Action-based permissions (e.g., read, write)
- Permission propagation through both resource and role hierarchies
- Node.js native test coverage

## Installation

Clone this repository or copy the files into your project:

```sh
git clone <your-repo-url>
cd rrbac
```

## Usage Example

```js
import { Resource, Role, RRBACSystem } from './rrbac.js';

// Create resources
dconst root = new Resource('root');
const folder = new Resource('folder');
const file = new Resource('file');
root.addChild(folder);
folder.addChild(file);

// Create roles
const admin = new Role('admin');
const user = new Role('user');
user.addParent(admin); // admin is senior to user

const roles = new Map([
  ['admin', admin],
  ['user', user],
]);

// Create RRBAC system
const rrbac = new RRBACSystem(root, roles);

// Assign permissions
rrbac.permissionAssignment(folder, user, 'read');

// Check access
console.log(rrbac.canAccess(user, file, 'read')); // true
console.log(rrbac.canAccess(admin, file, 'read')); // true
console.log(rrbac.canAccess(user, root, 'read')); // false
```

## API

### Classes

- `Resource(id: string)` — Represents a node in the resource hierarchy.
- `Role(id: string)` — Represents a role in the role hierarchy.
- `RRBACSystem(resourceRoot: Resource, roles: Map<string, Role>)` — Main access control system.

### Key Methods

- `Resource#addChild(child: Resource)` — Add a child resource.
- `Role#addParent(parent: Role)` — Add a parent (senior) role.
- `RRBACSystem#permissionAssignment(resource, role, action)` — Assign permission for a role to perform an action on a resource.
- `RRBACSystem#canAccess(role, resource, action)` — Check if a role can perform an action on a resource.

## Running Tests

This project uses Node.js native test runner (requires Node.js v18+):

```sh
npm test
```

## License

MIT
