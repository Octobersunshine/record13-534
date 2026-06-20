const express = require("express");
const { spawn } = require("child_process");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 60000;

app.use((req, res, next) => {
  req._scanTimer = setTimeout(() => {
    if (!res.headersSent) {
      res.status(504).json({ success: false, error: `请求超时（${SCAN_TIMEOUT_MS / 1000}秒），可通过环境变量 SCAN_TIMEOUT_MS 调整` });
    }
  }, SCAN_TIMEOUT_MS + 5000);

  const origEnd = res.end.bind(res);
  res.end = function (...args) {
    clearTimeout(req._scanTimer);
    origEnd(...args);
  };
  next();
});

const VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

function parseSeverityFilter(severity) {
  if (!severity || typeof severity !== "string") return null;
  const parts = severity
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  if (parts.length === 0) return null;
  const valid = parts.filter((s) => VALID_SEVERITIES.includes(s));
  if (valid.length === 0) return null;
  return valid;
}

function sanitizeImageName(name) {
  if (!name || typeof name !== "string") return null;
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > 256) return null;
  if (/[;&|`$(){}!#<>]/.test(trimmed)) return null;
  return trimmed;
}

function runTrivy(imageName) {
  return new Promise((resolve, reject) => {
    const trivyCmd = process.platform === "win32" ? "trivy.exe" : "trivy";
    const args = ["image", "--format", "json", "--no-progress", imageName];

    const child = spawn(trivyCmd, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn(arg);
    };

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 100 * 1024 * 1024) {
        settle(reject, new Error("扫描输出超过 100MB 限制，已终止"));
        killChild(child);
      }
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", (err) => {
      if (err.code === "ENOENT") {
        return settle(reject, new Error("未找到 Trivy 安全扫描工具，请先安装：https://trivy.dev"));
      }
      settle(reject, new Error(`启动扫描进程失败：${err.message}`));
    });

    child.on("close", (code) => {
      if (settled) return;

      if (code !== 0 && !stdout) {
        const stderrStr = stderr.toString();
        if (stderrStr.includes("unknown flag")) {
          return settle(reject, new Error("Trivy 参数不兼容，请检查 Trivy 版本"));
        }
        return settle(reject, new Error(`扫描失败（退出码 ${code}）：${stderrStr}`));
      }

      try {
        const result = JSON.parse(stdout.toString());
        settle(resolve, result);
      } catch (parseErr) {
        settle(reject, new Error("无法解析 Trivy 扫描结果"));
      }
    });

    timer = setTimeout(() => {
      killChild(child);
      settle(reject, new Error(`扫描超时（${SCAN_TIMEOUT_MS / 1000}秒限制），镜像过大或网络较慢，可设置环境变量 SCAN_TIMEOUT_MS 调整`));
    }, SCAN_TIMEOUT_MS);
  });
}

function killChild(child) {
  try {
    if (process.platform === "win32") {
      spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    } else {
      child.kill("SIGKILL");
    }
  } catch (_) {}
}

function extractVulnerabilities(trivyResult) {
  const vulnerabilities = [];

  if (!trivyResult.Results || !Array.isArray(trivyResult.Results)) {
    return vulnerabilities;
  }

  for (const target of trivyResult.Results) {
    if (!target.Vulnerabilities || !Array.isArray(target.Vulnerabilities)) continue;
    for (const vuln of target.Vulnerabilities) {
      vulnerabilities.push({
        target: target.Target || "",
        type: target.Type || "",
        vulnerabilityId: vuln.VulnerabilityID || "",
        pkgName: vuln.PkgName || "",
        installedVersion: vuln.InstalledVersion || "",
        fixedVersion: vuln.FixedVersion || "",
        severity: vuln.Severity || "UNKNOWN",
        title: vuln.Title || "",
        description: vuln.Description || "",
        primaryUrl: vuln.PrimaryURL || "",
        references: vuln.References || [],
      });
    }
  }

  return vulnerabilities;
}

function getSeveritySummary(vulnerabilities) {
  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of vulnerabilities) {
    const sev = (v.severity || "UNKNOWN").toUpperCase();
    if (summary[sev] !== undefined) {
      summary[sev]++;
    } else {
      summary["UNKNOWN"]++;
    }
  }
  return summary;
}

app.post("/scan", async (req, res) => {
  const { image, severity } = req.body;

  const imageName = sanitizeImageName(image);
  if (!imageName) {
    return res.status(400).json({
      success: false,
      error: "请提供有效的镜像名称（image 字段）",
    });
  }

  const severityFilter = parseSeverityFilter(severity);

  try {
    const trivyResult = await runTrivy(imageName);
    const allVulnerabilities = extractVulnerabilities(trivyResult);
    const vulnerabilities = severityFilter
      ? allVulnerabilities.filter((v) => severityFilter.includes((v.severity || "UNKNOWN").toUpperCase()))
      : allVulnerabilities;
    const severitySummary = getSeveritySummary(vulnerabilities);

    res.json({
      success: true,
      image: imageName,
      totalVulnerabilities: vulnerabilities.length,
      severityFilter: severityFilter || null,
      severitySummary,
      vulnerabilities,
    });
  } catch (err) {
    const statusCode = err.message.includes("未找到") ? 503 : 500;
    res.status(statusCode).json({
      success: false,
      image: imageName,
      error: err.message,
    });
  }
});

app.get("/scan", async (req, res) => {
  const image = req.query.image;
  const severity = req.query.severity;

  const imageName = sanitizeImageName(image);
  if (!imageName) {
    return res.status(400).json({
      success: false,
      error: "请提供有效的镜像名称（image 查询参数）",
    });
  }

  const severityFilter = parseSeverityFilter(severity);

  try {
    const trivyResult = await runTrivy(imageName);
    const allVulnerabilities = extractVulnerabilities(trivyResult);
    const vulnerabilities = severityFilter
      ? allVulnerabilities.filter((v) => severityFilter.includes((v.severity || "UNKNOWN").toUpperCase()))
      : allVulnerabilities;
    const severitySummary = getSeveritySummary(vulnerabilities);

    res.json({
      success: true,
      image: imageName,
      totalVulnerabilities: vulnerabilities.length,
      severityFilter: severityFilter || null,
      severitySummary,
      vulnerabilities,
    });
  } catch (err) {
    const statusCode = err.message.includes("未找到") ? 503 : 500;
    res.status(statusCode).json({
      success: false,
      image: imageName,
      error: err.message,
    });
  }
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "image-security-scanner" });
});

app.listen(PORT, () => {
  console.log(`镜像安全扫描服务已启动：http://localhost:${PORT}`);
  console.log(`扫描超时限制：${SCAN_TIMEOUT_MS / 1000}秒（可通过 SCAN_TIMEOUT_MS 环境变量调整）`);
  console.log(`POST /scan  - 提交 JSON {"image": "镜像名", "severity": "CRITICAL,HIGH"} 进行扫描`);
  console.log(`GET  /scan?image=镜像名&severity=CRITICAL,HIGH  - 通过查询参数扫描`);
  console.log(`       severity 可选值：CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN（逗号分隔多个）`);
  console.log(`GET  /health - 健康检查`);
});
