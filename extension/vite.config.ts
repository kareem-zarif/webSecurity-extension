import { copyFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

function copyManifest(): Plugin {
  return {
    name: 'copy-extension-manifest',
    apply: 'build',
    async closeBundle() {
      const outputDirectory = resolve(import.meta.dirname, 'dist');
      await mkdir(outputDirectory, { recursive: true });
      await copyFile(
        resolve(import.meta.dirname, 'manifest.json'),
        resolve(outputDirectory, 'manifest.json'),
      );
    },
  };
}

export default defineConfig({
  plugins: [react(), copyManifest()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      input: {
        popup: resolve(import.meta.dirname, 'popup.html'),
      },
      output: {
        entryFileNames: 'assets/[name].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});

