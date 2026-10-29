require('dotenv').config();
const express = require('express');
const pool = require('./db');

const complaintsRouter = require('./routes/complaints');
const { router: wardenRouter } = require('./routes/warden');
const technicianRouter = require('./routes/technician');
const authRouter = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

// Routes
app.use('/api/auth', authRouter);
app.use('/api/complaints', complaintsRouter);
app.use('/api/warden/complaints', wardenRouter);
app.use('/api/technician/assignments', technicianRouter);

// Health check endpoint verifying database connectivity with SELECT 1
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT 1 AS status');
    if (result && result.rows) {
      return res.status(200).json({
        status: 'ok',
        database: 'connected',
        timestamp: new Date().toISOString(),
      });
    }
    return res.status(500).json({
      status: 'error',
      database: 'unexpected_response',
      message: 'Health check query returned unexpected result.',
    });
  } catch (err) {
    // Log safe error message on server side; do not expose internal error/credentials to client
    console.error('Database connection error during health check:', err.message);
    return res.status(500).json({
      status: 'error',
      database: 'disconnected',
      message: 'Database health check failed.',
    });
  }
});

// Generic 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`HostelFix backend running on port ${PORT}`);
  });
}

module.exports = app;
