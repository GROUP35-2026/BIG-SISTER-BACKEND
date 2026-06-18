import mysql from 'mysql2/promise';

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bigsister',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Explicitly test the connection and log it when the server boots
pool.getConnection()
  .then(connection => {
    console.log('🗄️  Connected to MariaDB database: bigsister');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

export default pool;