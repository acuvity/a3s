import { defineConfig } from "vite";
import { viteStaticCopyModulePlugin } from "vite-plugin-static-copy-modules";
import react from "@vitejs/plugin-react";
import svgr from "vite-plugin-svgr";
import fs from "fs";
import path from "path";
import bodyParser from 'body-parser';

const intercepterPlugin = () => ({
  name: 'intercepter-plugin',
  configureServer(server) {
    server.middlewares.use(bodyParser.urlencoded({ extended: true }));
    server.middlewares.use('/saml/callback', (req, res) => {
      res.writeHead(302, {
        Location: `/saml-verify?SAMLResponse=${req.body.SAMLResponse}&relayState=${req.body.RelayState}`
      });
      res.end();
    })
  },
});

// https://vitejs.dev/config/
export default defineConfig({
  server: {
    fs: {
      cachedChecks: false,
    },
    https: {
      key: fs.readFileSync(
        "../backend/dev/data/certificates/public-server-key.pem"
      ),
      cert: fs.readFileSync(
        "../backend/dev/data/certificates/public-server-cert.pem"
      ),
      passphrase: "acuvity",
    },
  },
  plugins: [
    react(),
    svgr(),
    intercepterPlugin(),
    viteStaticCopyModulePlugin([
      {
        moduleName: "monaco-editor",
        define: "import.meta.env.MONACO_PATH",
        targets: (modulePath, publicPath) => [
          {
            src: path.resolve(modulePath, "min"),
            dest: publicPath,
          },
          {
            src: path.resolve(modulePath, "min-maps"),
            dest: publicPath,
          },
        ],
      },
    ]),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  }
});
