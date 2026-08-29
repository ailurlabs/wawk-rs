// browser_test_runner.js — Headless browser E2E test runner using puppeteer
import puppeteer from 'puppeteer';
import { createServer } from 'http';
import { readFile } from 'fs/promises';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const PORT = 8765;

const MIME_TYPES = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.mjs': 'application/javascript',
    '.wasm': 'application/wasm',
    '.json': 'application/json',
    '.css': 'text/css',
};

// Simple static file server
const server = createServer(async (req, res) => {
    let urlPath = req.url.split('?')[0];
    if (urlPath === '/') urlPath = '/index.html';

    const filePath = join(REPO_ROOT, urlPath);
    const ext = extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    try {
        const data = await readFile(filePath);
        res.writeHead(200, {
            'Content-Type': contentType,
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
        });
        res.end(data);
    } catch (e) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end(`Not found: ${urlPath}`);
    }
});

async function run() {
    await new Promise(resolve => server.listen(PORT, resolve));
    console.log(`Static server running on http://localhost:${PORT}`);

    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security'],
        });

        const page = await browser.newPage();

        // Collect console messages
        const logs = [];
        page.on('console', msg => {
            logs.push(msg.text());
            console.log(msg.text());
        });
        page.on('pageerror', err => {
            console.error(`PAGE ERROR: ${err.message}`);
        });

        // Navigate to the test page
        const testUrl = `http://localhost:${PORT}/crates/wawk-bindgen/tests/browser_e2e.html`;
        console.log(`Navigating to: ${testUrl}`);
        await page.goto(testUrl, { waitUntil: 'networkidle0', timeout: 30000 });

        // Wait for test results to appear
        await page.waitForFunction(
            () => {
                const el = document.getElementById('results');
                return el && el.textContent.includes('Results:');
            },
            { timeout: 30000 }
        );

        // Small delay to ensure all tests completed
        await new Promise(r => setTimeout(r, 1000));

        // Extract results
        const resultText = await page.evaluate(() => {
            return document.getElementById('results').textContent;
        });

        // Parse pass/fail counts
        const match = resultText.match(/Results: (\d+) passed, (\d+) failed/);
        if (match) {
            const passed = parseInt(match[1]);
            const failed = parseInt(match[2]);
            console.log(`\n=== Browser E2E Summary: ${passed} passed, ${failed} failed ===`);
            if (failed > 0) {
                process.exitCode = 1;
            }
        } else {
            console.error('Could not parse test results');
            process.exitCode = 1;
        }
    } catch (err) {
        console.error(`Test runner error: ${err.message}`);
        process.exitCode = 1;
    } finally {
        if (browser) await browser.close();
        server.close();
    }
}

run();
