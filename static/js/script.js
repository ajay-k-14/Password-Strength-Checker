/*
 * script.js
 * ---------
 * All password analysis for the live UI happens HERE, in the browser,
 * so that keystrokes are never sent to the server. The Flask API
 * (/api/analyze) exists mainly so the logic can also be exercised
 * server-side (e.g. for automated tests or non-JS clients), but the
 * page you are using does not call it on every keystroke.
 *
 * Nothing in this file ever sends the password anywhere over the
 * network, writes it to localStorage/sessionStorage, or logs it to
 * the console.
 */

(function () {
  "use strict";

  // A small local sample of common/weak passwords, mirrored from
  // data/common_passwords.txt, used purely for client-side checking.
  const COMMON_PASSWORDS = new Set([
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "password123", "admin", "welcome",
    "letmein", "iloveyou", "monkey", "football", "dragon", "master",
    "sunshine", "princess", "qwertyuiop", "123123", "000000", "1q2w3e4r",
    "zaq12wsx", "trustno1", "superman", "batman", "freedom", "whatever",
    "qazwsx", "passw0rd", "p@ssw0rd", "p@ssword", "starwars", "shadow",
    "michael", "jennifer", "jordan23", "hunter2", "letmein123",
    "welcome123", "admin123", "root", "toor", "changeme", "default",
    "guest", "test123", "demo123",
  ]);

  const KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "qwertyuiop",
    "asdfghjkl", "zxcvbnm",
  ];

  const SPECIAL_REGEX = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~`]/;

  const POLICY = {
    minLength: 12,
    recommendedLength: 16,
  };

  function hasUpper(pw) { return /[A-Z]/.test(pw); }
  function hasLower(pw) { return /[a-z]/.test(pw); }
  function hasNumber(pw) { return /[0-9]/.test(pw); }
  function hasSpecial(pw) { return SPECIAL_REGEX.test(pw); }

  function characterSetSize(pw) {
    let size = 0;
    if (hasLower(pw)) size += 26;
    if (hasUpper(pw)) size += 26;
    if (hasNumber(pw)) size += 10;
    if (hasSpecial(pw)) size += 27; // approx count of special char set used
    return size || 1;
  }

  function estimateEntropyBits(pw) {
    if (!pw) return 0;
    const alphabet = characterSetSize(pw);
    return Math.round(pw.length * Math.log2(alphabet) * 10) / 10;
  }

  function hasRepeatedChars(pw, runLength = 4) {
    const re = new RegExp("(.)\\1{" + (runLength - 1) + ",}");
    return re.test(pw);
  }

  function hasSequentialChars(pw, runLength = 4) {
    const lowered = pw.toLowerCase();
    const ascending = "abcdefghijklmnopqrstuvwxyz0123456789";
    const descending = ascending.split("").reverse().join("");
    for (const seq of [ascending, descending]) {
      for (let i = 0; i <= seq.length - runLength; i++) {
        if (lowered.includes(seq.slice(i, i + runLength))) return true;
      }
    }
    return false;
  }

  function hasKeyboardPattern(pw) {
    const lowered = pw.toLowerCase();
    return KEYBOARD_PATTERNS.some((p) => lowered.includes(p));
  }

  function normalizeForDictionary(pw) {
    const map = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
    return pw
      .toLowerCase()
      .split("")
      .map((ch) => map[ch] || ch)
      .join("");
  }

  function isCommonPassword(pw) {
    const lowered = pw.toLowerCase();
    const normalized = normalizeForDictionary(pw);
    if (COMMON_PASSWORDS.has(lowered) || COMMON_PASSWORDS.has(normalized)) {
      return true;
    }
    const strippedRaw = lowered.replace(/[\d!@#$%^&*_\-]+$/, "");
    const strippedNormalized = normalizeForDictionary(strippedRaw);
    return (
      strippedRaw !== "" &&
      (COMMON_PASSWORDS.has(strippedRaw) || COMMON_PASSWORDS.has(strippedNormalized))
    );
  }

  function strengthLabel(score) {
    if (score <= 20) return "Very Weak";
    if (score <= 40) return "Weak";
    if (score <= 60) return "Moderate";
    if (score <= 80) return "Strong";
    return "Very Strong";
  }

  function strengthColor(score) {
    if (score <= 20) return "var(--danger)";
    if (score <= 40) return "var(--danger)";
    if (score <= 60) return "var(--warning)";
    if (score <= 80) return "var(--accent)";
    return "var(--success)";
  }

  function analyzePassword(password) {
    const length = password.length;

    const checks = {
      minimum_length: length >= POLICY.minLength,
      recommended_length: length >= POLICY.recommendedLength,
      uppercase: hasUpper(password),
      lowercase: hasLower(password),
      number: hasNumber(password),
      special: hasSpecial(password),
    };

    const varietyCount = [checks.uppercase, checks.lowercase, checks.number, checks.special]
      .filter(Boolean).length;
    checks.good_variety = varietyCount >= 3;

    const warnings = [];
    const recommendations = [];

    if (length === 0) {
      warnings.push("Password is empty.");
    } else if (length < POLICY.minLength) {
      warnings.push(`Password is shorter than ${POLICY.minLength} characters.`);
      recommendations.push(`Use at least ${POLICY.minLength} characters.`);
    }

    if (length >= POLICY.minLength && length < POLICY.recommendedLength) {
      recommendations.push(`Consider ${POLICY.recommendedLength}+ characters for stronger protection.`);
    }

    if (!checks.uppercase) recommendations.push("Add uppercase letters.");
    if (!checks.lowercase) recommendations.push("Add lowercase letters.");
    if (!checks.number) recommendations.push("Add numbers.");
    if (!checks.special) recommendations.push("Add special characters.");

    const repeated = length ? hasRepeatedChars(password) : false;
    const sequential = length ? hasSequentialChars(password) : false;
    const keyboard = length ? hasKeyboardPattern(password) : false;
    const common = length ? isCommonPassword(password) : false;

    if (repeated) warnings.push("Contains a long run of the same character.");
    if (sequential) warnings.push("Contains a sequential pattern (e.g. 1234, abcd).");
    if (keyboard) warnings.push("Contains a keyboard-walk pattern (e.g. qwerty).");
    if (common) warnings.push("Matches a common/leaked password or an obvious variation of one.");

    if (repeated || sequential || keyboard || common) {
      recommendations.push("Avoid common words, patterns, and predictable substitutions.");
    }

    if (length > 0 && varietyCount >= 3 && length < POLICY.recommendedLength) {
      recommendations.push("Consider using a long, random passphrase instead of a short complex password.");
    }

    let score = 0;
    const lengthRatio = length ? Math.min(length / POLICY.recommendedLength, 1.5) : 0;
    score += Math.min(lengthRatio * 50, 55);
    score += varietyCount * 6.25;
    const entropy = estimateEntropyBits(password);
    score += Math.min(entropy / 4, 20);

    if (common) score -= 45;
    if (keyboard) score -= 20;
    if (sequential) score -= 15;
    if (repeated) score -= 15;
    if (length < POLICY.minLength && length > 0) score -= 10;

    score = Math.max(0, Math.min(100, Math.round(score)));
    if (length === 0) score = 0;

    const strength = strengthLabel(score);
    if ((strength === "Strong" || strength === "Very Strong") && recommendations.length === 0) {
      recommendations.push("Great job — keep using a unique password for every account.");
    }

    return { score, strength, length, checks, entropy_estimate: entropy, warnings, recommendations };
  }

  // ---------------- DOM wiring ----------------

  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-visibility");
  const strengthLabelEl = document.getElementById("strength-label");
  const meterFill = document.getElementById("meter-fill");
  const scoreValue = document.getElementById("score-value");
  const entropyValue = document.getElementById("entropy-value");
  const checksList = document.getElementById("checks-list");
  const warningsBlock = document.getElementById("warnings-block");
  const warningsList = document.getElementById("warnings-list");
  const recommendationsBlock = document.getElementById("recommendations-block");
  const recommendationsList = document.getElementById("recommendations-list");

  const CHECK_LABELS = {
    minimum_length: "Minimum length (12+)",
    recommended_length: "Recommended length (16+)",
    uppercase: "Uppercase letter",
    lowercase: "Lowercase letter",
    number: "Number",
    special: "Special character",
    good_variety: "Good character variety",
  };

  function renderResult(result) {
    strengthLabelEl.textContent = result.length ? result.strength : "—";
    meterFill.style.width = result.score + "%";
    meterFill.style.background = strengthColor(result.score);
    scoreValue.textContent = `${result.score} / 100`;
    entropyValue.textContent = `~${result.entropy_estimate} bits (estimate)`;

    checksList.innerHTML = "";
    Object.entries(CHECK_LABELS).forEach(([key, label]) => {
      const li = document.createElement("li");
      const passed = !!result.checks[key];
      li.className = passed ? "pass" : "fail";
      li.textContent = (passed ? "\u2713 " : "\u2717 ") + label;
      checksList.appendChild(li);
    });

    warningsList.innerHTML = "";
    if (result.warnings.length) {
      result.warnings.forEach((w) => {
        const li = document.createElement("li");
        li.textContent = "\u26A0 " + w;
        warningsList.appendChild(li);
      });
      warningsBlock.hidden = false;
    } else {
      warningsBlock.hidden = true;
    }

    recommendationsList.innerHTML = "";
    if (result.recommendations.length) {
      result.recommendations.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = "\u2022 " + r;
        recommendationsList.appendChild(li);
      });
      recommendationsBlock.hidden = false;
    } else {
      recommendationsBlock.hidden = true;
    }
  }

  passwordInput.addEventListener("input", () => {
    const result = analyzePassword(passwordInput.value);
    renderResult(result);
  });

  // Initialize with an empty-state render.
  renderResult(analyzePassword(""));

  toggleBtn.addEventListener("click", () => {
    const isHidden = passwordInput.type === "password";
    passwordInput.type = isHidden ? "text" : "password";
    toggleBtn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    toggleBtn.textContent = isHidden ? "\u{1F576}" : "\u{1F441}";
  });

  // ---------------- Generator ----------------

  const genLength = document.getElementById("gen-length");
  const genLengthValue = document.getElementById("gen-length-value");
  const genUppercase = document.getElementById("gen-uppercase");
  const genLowercase = document.getElementById("gen-lowercase");
  const genNumbers = document.getElementById("gen-numbers");
  const genSpecial = document.getElementById("gen-special");
  const generateBtn = document.getElementById("generate-btn");
  const generatedOutput = document.getElementById("generated-output");
  const copyBtn = document.getElementById("copy-btn");
  const copyStatus = document.getElementById("copy-status");

  genLength.addEventListener("input", () => {
    genLengthValue.textContent = genLength.value;
  });

  async function requestGeneratedPassword() {
    const payload = {
      length: parseInt(genLength.value, 10),
      use_uppercase: genUppercase.checked,
      use_lowercase: genLowercase.checked,
      use_numbers: genNumbers.checked,
      use_special: genSpecial.checked,
    };

    generateBtn.disabled = true;
    copyStatus.textContent = "";

    try {
      const response = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();

      if (!response.ok) {
        generatedOutput.value = "";
        copyStatus.textContent = data.error || "Could not generate password.";
        copyStatus.style.color = "var(--danger)";
        return;
      }

      generatedOutput.value = data.password;
      copyStatus.textContent = "";
    } catch (err) {
      copyStatus.textContent = "Network error while generating password.";
      copyStatus.style.color = "var(--danger)";
    } finally {
      generateBtn.disabled = false;
    }
  }

  generateBtn.addEventListener("click", requestGeneratedPassword);

  copyBtn.addEventListener("click", async () => {
    if (!generatedOutput.value) {
      copyStatus.textContent = "Generate a password first.";
      copyStatus.style.color = "var(--warning)";
      return;
    }
    try {
      await navigator.clipboard.writeText(generatedOutput.value);
      copyStatus.textContent = "Copied to clipboard.";
      copyStatus.style.color = "var(--success)";
    } catch (err) {
      copyStatus.textContent = "Could not copy automatically — please copy manually.";
      copyStatus.style.color = "var(--warning)";
    }
  });
})();
