import express from 'express';
import net, { Socket } from 'net';
import path from 'path';
import fs from 'fs';

const app = express();
app.use(express.urlencoded({ extended: true }));

function renderTemplate(filePath: string, vars: Record<string, string>): string {
  let content = fs.readFileSync(filePath, 'utf-8');
  for (const key in vars) {
    content = content.replace(`\${${key}}`, vars[key]);
  }
  return content;
}

app.get('/', (_req, res) => {
  const html = renderTemplate(path.join(__dirname, 'pages/index.html'), {
    user: 'John',
    time: new Date().toLocaleTimeString()
  });
  res.send(html);
});

app.post('/search', (_req, res) => {
  const searched = `${_req.body.searched ?? ""}`;
  const data = [
    { "id": 1, "name": "Apple", "color": "Red", "price": 0.99, "stock": 120 },
    { "id": 2, "name": "Banana", "color": "Yellow", "price": 0.59, "stock": 200 },
    { "id": 3, "name": "Orange", "color": "Orange", "price": 1.29, "stock": 150 },
    { "id": 4, "name": "Kiwi", "color": "Brown", "price": 1.49, "stock": 80 },
    { "id": 5, "name": "Strawberry", "color": "Red", "price": 2.99, "stock": 60 },
    { "id": 6, "name": "Blueberry", "color": "Blue", "price": 3.49, "stock": 50 },
    { "id": 7, "name": "Pineapple", "color": "Yellow", "price": 2.49, "stock": 40 },
    { "id": 8, "name": "Mango", "color": "Orange", "price": 1.99, "stock": 70 },
    { "id": 9, "name": "Grapes", "color": "Purple", "price": 2.19, "stock": 100 },
    { "id": 10, "name": "Watermelon", "color": "Green", "price": 4.99, "stock": 30 }
  ]

  const searchResult = data.filter(d => d.name.toLowerCase().includes(searched.toLowerCase()))
    .map(d => `${d.name} (${d.color}) - ${d.price}€`)
    .join("<br/>");

  const html = renderTemplate(path.join(__dirname, 'pages/search.html'), {
    searched: searched,
    searchResult: searchResult
  });
  res.send(html);
});

app.listen(80, () => {
  console.log('HTTP server on 80');
});

const ftpServer = net.createServer((socket: Socket) => {
  socket.write('220 Fake FTP ready\r\n');
});
ftpServer.listen(21, () => {
  console.log('Fake FTP on 21');
});

const sshFake = net.createServer((socket: Socket) => {
  socket.write('SSH-2.0-OpenSSH_Fake\r\n');
});
sshFake.listen(22, () => {
  console.log('Fake SSH on 22');
});


