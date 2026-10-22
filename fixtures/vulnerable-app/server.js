const jwt = require('jsonwebtoken');
const crypto = require('crypto');

app.use(cors({ origin: '*' }));
const token = jwt.sign({ id: 1 }, 'secret123');
jwt.verify(token, key, { algorithms: ['none'] });
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
const h = crypto.createHash('md5').update(pw).digest('hex');
