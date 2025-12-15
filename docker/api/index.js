const express = require('express');
const app = express();
const PORT = 8082;

app.get('/', (req, res) => {
    res.json({ message: 'Hola desde el API (Node)' });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`API escuchando en http://0.0.0.0:${PORT}`);
});