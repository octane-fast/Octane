import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  base: './',
  build: {
    modulePreload: false,
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
        viewer: resolve(__dirname, 'src/popup/viewer.html'),
        confirm: resolve(__dirname, 'src/popup/confirm.html'),
        background: resolve(__dirname, 'src/background/index.ts'),
        offscreen: resolve(__dirname, 'src/offscreen/index.ts'),
        'pvac-worker': resolve(__dirname, 'src/offscreen/worker.ts'),
        content: resolve(__dirname, 'src/content/index.ts'),
        inpage: resolve(__dirname, 'src/inpage/index.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: 'assets/[name].[ext]',
      },
    },
  },
});
