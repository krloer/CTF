const puppeteer = require("puppeteer");

const FLAG = process.env.FLAG || "S2G{fake_flag}";
const CHALL_URL = process.env.CHALL_URL || "http://localhost:8080";

async function visit(recipe_id) {
  let browser;

  try {
    browser = await puppeteer.launch({
      headless: "new",
      pipe: true,
      args: [
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-gpu",
        "--disable-sync",
        "--disable-translate",
        "--hide-scrollbars",
        "--metrics-recording-only",
        "--mute-audio",
        "--no-first-run",
        "--no-sandbox",
        "--safebrowsing-disable-auto-update",
      ],
      dumpio: true,
    });
    let page = await browser.newPage();

    const url = `${CHALL_URL}/recipe/${recipe_id}`;
    await page.setCookie({ name: "flag", value: FLAG, url: CHALL_URL });
    await page.goto(url, {
      timeout: 3000,
      waitUntil: "domcontentloaded",
    });

    await page.waitForTimeout(3000);

    await page.close();
    await browser.close();
    browser = null;
    console.log("Done visiting", url);
  } catch (err) {
    console.log(err);
    return { status: false, message: "Failed to visit page." };
  } finally {
    if (browser) await browser.close();
    return { status: true, message: "Done visiting!" };
  }
}

module.exports = { visit };
