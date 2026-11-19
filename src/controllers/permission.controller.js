import { grants } from '../config/permissions.js';
const me = async (req, res) => res.json({ success: true, data: { role: req.user.role, depotIds: req.user.role === 'super_admin' ? ['*'] : req.user.depotIds, permissions: grants[req.user.role] || [] } });
export { me };
