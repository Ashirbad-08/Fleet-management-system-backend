// Reuse these permission names on future fleet routes to enforce the access matrix.
const grants = {
  super_admin: ['dashboard:read', 'vehicles:read', 'vehicles:create', 'vehicles:update', 'vehicles:delete', 'vehicles:export', 'telemetry:read', 'devices:read', 'geofences:read', 'geofences:create', 'geofences:update', 'geofences:delete', 'alerts:read', 'alerts:dismiss', 'esg:read', 'users:read', 'users:create', 'users:update', 'users:delete', 'settings:read', 'settings:update'],
  admin: ['dashboard:read', 'vehicles:read', 'vehicles:create', 'vehicles:update', 'vehicles:export', 'telemetry:read', 'devices:read', 'geofences:read', 'geofences:create', 'geofences:update', 'alerts:read', 'alerts:dismiss', 'esg:read','users:create','users:read', 'settings:read'],
  operator: ['dashboard:read', 'vehicles:read', 'vehicles:export', 'telemetry:read', 'devices:read', 'geofences:read', 'alerts:read', 'esg:read'],
};

export { grants };
