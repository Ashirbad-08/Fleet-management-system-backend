import mongoose from 'mongoose';

const DB_STATES = {
  0: 'disconnected',
  1: 'connected',
  2: 'connecting',
  3: 'disconnecting',
};

const getHealth = () => {
  const dbState = DB_STATES[mongoose.connection.readyState] || 'unknown';

  return {
    status: dbState === 'connected' ? 'ok' : 'degraded',
    uptime: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    database: dbState,
  };
};

export { getHealth };
