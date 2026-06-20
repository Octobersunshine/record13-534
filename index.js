const express = require("express");
const { execFile } = require("child_process");
const path = require("path");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

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

    execFile(trivyCmd, args, { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }, (error, stdout, stderr) => {
      if (error) {
        if (error.killed) {
          return reject(new Error("扫描超时（5分钟限制）"));
        }
        const stderrStr = (stderr || "").toString();
        if (stderrStr.includes("not found") || stderrStr.includes("not recognized")) {
          return reject(new Error("未找到 Trivy 安全扫描工具，请先安装：https://trivy.dev"));
        }
        if (stderrStr.includes("unknown flag")) {
          return reject(new Error("Trivy 参数不兼容，请检查 Trivy 版本"));
        }
        if (stdout) {
          try {
            const result = JSON.parse(stdout.toString());
            return resolve(result);
          } catch (_) {}
        }
        return reject(new Error(`扫描失败：${stderrStr || error.message}`));
      }
      try {
        const result = JSON.parse(stdout.toString());
        resolve(result);
      } catch (parseErr) {
        reject(new Error("无法解析 Trivy 扫描结果"));
      }
    });
  });
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
  const { image } = req.body;

  const imageName = sanitizeImageName(image);
  if (!imageName) {
    return res.status(400).json({
      success: false,
      error: "请提供有效的镜像名称（image 字段）",
    });
  }

  try {
    const trivyResult = await runTrivy(imageName);
    const vulnerabilities = extractVulnerabilities(trivyResult);
    const severitySummary = getSeveritySummary(vulnerabilities);

    res.json({
      success: true,
      image: imageName,
      totalVulnerabilities: vulnerabilities.length,
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

  const imageName = sanitizeImageName(image);
  if (!imageName) {
    return res.status(400).json({
      success: false,
      error: "请提供有效的镜像名称（image 查询参数）",
    });
  }

  try {
    const trivyResult = await runTrivy(imageName);
    const vulnerabilities = extractVulnerabilities(trivyResult);
    const severitySummary = getSeveritySummary(vulnerabilities);

    res.json({
      success: true,
      image: imageName,
      totalVulnerabilities: vulnerabilities.length,
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
  console.log(`POST /scan  - 提交 JSON {"image": "镜像名"} 进行扫描`);
  console.log(`GET  /scan?image=镜像名  - 通过查询参数扫描`);
  console.log(`GET  /health - 健康检查`);
});
