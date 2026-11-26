import base64
import os

def generate_banner():
    logo_path = os.path.join("docs", "assets", "andhak-logo.png")
    out_path = os.path.join("docs", "assets", "andhak-banner-animated.svg")

    with open(logo_path, "rb") as f:
        b64_logo = base64.b64encode(f.read()).decode("utf-8")

    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 330" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
  <defs>
    <!-- Background Gradient -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#080C14" />
      <stop offset="50%" stop-color="#0D121D" />
      <stop offset="100%" stop-color="#070A10" />
    </linearGradient>

    <!-- Top Laser Accent -->
    <linearGradient id="topLaserGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#1E293B" stop-opacity="0.2" />
      <stop offset="20%" stop-color="#A92532" />
      <stop offset="50%" stop-color="#FF3344" />
      <stop offset="70%" stop-color="#FF8800" />
      <stop offset="85%" stop-color="#A92532" />
      <stop offset="100%" stop-color="#1E293B" stop-opacity="0.2" />
    </linearGradient>

    <!-- Ambient Red Core Glow -->
    <radialGradient id="ambientAura" cx="50%" cy="40%" r="45%">
      <stop offset="0%" stop-color="#FF1A2A" stop-opacity="0.38" />
      <stop offset="40%" stop-color="#A92532" stop-opacity="0.18" />
      <stop offset="80%" stop-color="#080C14" stop-opacity="0" />
    </radialGradient>

    <!-- Eye Laser Radial -->
    <radialGradient id="eyeGlowCore" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="1" />
      <stop offset="25%" stop-color="#FF2B3C" stop-opacity="0.95" />
      <stop offset="65%" stop-color="#CC0018" stop-opacity="0.6" />
      <stop offset="100%" stop-color="#FF0022" stop-opacity="0" />
    </radialGradient>

    <!-- Scanning Radar Sweep Beam -->
    <linearGradient id="scanBeam" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#FF2E3F" stop-opacity="0" />
      <stop offset="80%" stop-color="#FF2E3F" stop-opacity="0.08" />
      <stop offset="98%" stop-color="#FF3344" stop-opacity="0.6" />
      <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.9" />
    </linearGradient>

    <!-- Metallic Title Gradient -->
    <linearGradient id="titleGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#FFFFFF" />
      <stop offset="60%" stop-color="#F1F5F9" />
      <stop offset="100%" stop-color="#CBD5E1" />
    </linearGradient>

    <!-- Neon Glow Filter -->
    <filter id="glowFilter" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="5" result="blur1" />
      <feGaussianBlur stdDeviation="12" result="blur2" />
      <feMerge>
        <feMergeNode in="blur2" />
        <feMergeNode in="blur1" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>

    <!-- Intense Eye Flare Filter -->
    <filter id="eyeFlare" x="-100%" y="-100%" width="300%" height="300%">
      <feGaussianBlur stdDeviation="3" result="blur" />
      <feComponentTransfer in="blur" result="bright">
        <feFuncA type="linear" slope="2" />
      </feComponentTransfer>
      <feMerge>
        <feMergeNode in="bright" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>

    <!-- Cyber Grid Pattern -->
    <pattern id="cyberGrid" width="30" height="30" patternUnits="userSpaceOnUse">
      <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#1E293B" stroke-width="0.5" stroke-opacity="0.35" />
      <circle cx="0" cy="0" r="0.8" fill="#A92532" fill-opacity="0.4" />
    </pattern>
  </defs>

  <style>
    @keyframes floatAnimation {{
      0%, 100% {{
        transform: translateY(0px);
      }}
      50% {{
        transform: translateY(-5px);
      }}
    }}

    @keyframes eyePulseAnimation {{
      0%, 100% {{
        opacity: 0.75;
        transform: scale(0.95);
      }}
      50% {{
        opacity: 1;
        transform: scale(1.18);
      }}
      85% {{
        opacity: 0.6;
        transform: scale(0.9);
      }}
      90% {{
        opacity: 1;
        transform: scale(1.3);
      }}
      95% {{
        opacity: 0.7;
        transform: scale(0.95);
      }}
    }}

    @keyframes auraPulse {{
      0%, 100% {{
        opacity: 0.55;
        transform: scale(0.96);
      }}
      50% {{
        opacity: 0.95;
        transform: scale(1.08);
      }}
    }}

    @keyframes scanBeamMove {{
      0% {{
        transform: translateY(10px);
        opacity: 0;
      }}
      15% {{
        opacity: 0.85;
      }}
      85% {{
        opacity: 0.85;
      }}
      100% {{
        transform: translateY(280px);
        opacity: 0;
      }}
    }}

    @keyframes topLaserSweep {{
      0%, 100% {{
        transform: translateX(-12%);
        opacity: 0.7;
      }}
      50% {{
        transform: translateX(12%);
        opacity: 1;
      }}
    }}

    @keyframes titleGlow {{
      0%, 100% {{
        filter: drop-shadow(0 0 8px rgba(255, 30, 40, 0.45)) drop-shadow(0 0 20px rgba(169, 37, 50, 0.2));
      }}
      50% {{
        filter: drop-shadow(0 0 16px rgba(255, 50, 65, 0.85)) drop-shadow(0 0 32px rgba(255, 40, 55, 0.4));
      }}
    }}

    @keyframes blinkLed {{
      0%, 100% {{ opacity: 1; }}
      50% {{ opacity: 0.3; }}
    }}

    .logo-float {{
      animation: floatAnimation 4s ease-in-out infinite;
      transform-origin: 480px 100px;
    }}

    .eye-pulse {{
      animation: eyePulseAnimation 4s ease-in-out infinite;
      transform-origin: center;
    }}

    .aura-anim {{
      animation: auraPulse 4s ease-in-out infinite;
      transform-origin: 480px 105px;
    }}

    .scan-anim {{
      animation: scanBeamMove 5s cubic-bezier(0.4, 0, 0.2, 1) infinite;
    }}

    .laser-sweep {{
      animation: topLaserSweep 6s ease-in-out infinite;
    }}

    .title-anim {{
      animation: titleGlow 3.5s ease-in-out infinite;
    }}

    .led-green {{ animation: blinkLed 2s ease-in-out infinite; }}
    .led-red {{ animation: blinkLed 1.6s ease-in-out infinite 0.3s; }}
    .led-cyan {{ animation: blinkLed 2.4s ease-in-out infinite 0.7s; }}
    .led-amber {{ animation: blinkLed 1.8s ease-in-out infinite 1.1s; }}
  </style>

  <!-- Container Base -->
  <rect width="960" height="330" rx="12" fill="url(#bgGrad)" stroke="#1E293B" stroke-width="1.5" />

  <!-- Cyber Grid Overlay -->
  <rect width="960" height="330" rx="12" fill="url(#cyberGrid)" />

  <!-- Top Laser Accent Bar (Reflecting user header styling) -->
  <g class="laser-sweep">
    <rect x="-100" y="0" width="1160" height="3.5" fill="url(#topLaserGrad)" />
    <rect x="-100" y="0" width="1160" height="1.5" fill="#FFF" opacity="0.4" />
  </g>

  <!-- Corner Telemetry Markers -->
  <g fill="none" stroke="#A92532" stroke-width="1.2" opacity="0.6">
    <!-- Top-Left -->
    <path d="M 18 36 L 18 18 L 36 18" />
    <circle cx="18" cy="18" r="2" fill="#FF3344" />

    <!-- Top-Right -->
    <path d="M 942 36 L 942 18 L 924 18" />
    <circle cx="942" cy="18" r="2" fill="#FF3344" />

    <!-- Bottom-Left -->
    <path d="M 18 294 L 18 312 L 36 312" />
    <circle cx="18" cy="312" r="2" fill="#FF3344" />

    <!-- Bottom-Right -->
    <path d="M 942 294 L 942 312 L 924 312" />
    <circle cx="942" cy="312" r="2" fill="#FF3344" />
  </g>

  <!-- Top Corner Telemetry Text -->
  <text x="42" y="28" font-family="monospace" font-size="9" fill="#64748B" letter-spacing="1.5">SYS://EDR.CORE.ONLINE</text>
  <text x="918" y="28" text-anchor="end" font-family="monospace" font-size="9" fill="#64748B" letter-spacing="1.5">DEFENSE-GRADE TELEMETRY</text>

  <!-- Ambient Red Core Aura -->
  <circle class="aura-anim" cx="480" cy="102" r="160" fill="url(#ambientAura)" />

  <!-- Active Radar Scanning Beam -->
  <g class="scan-anim">
    <rect x="180" y="0" width="600" height="32" fill="url(#scanBeam)" />
    <line x1="160" y1="32" x2="800" y2="32" stroke="#FF4D5E" stroke-width="1.5" opacity="0.9" filter="url(#glowFilter)" />
  </g>

  <!-- Logo Group with Floating & Eye Flare Animation -->
  <g class="logo-float">
    <!-- Centered Mask Image (132x132, centered at x=480, y=102 -> x=414, y=36) -->
    <image href="data:image/png;base64,{b64_logo}" x="414" y="36" width="132" height="132" preserveAspectRatio="xMidYMid meet" />

    <!-- Left Eye Glowing Iris & Laser Aura -->
    <g class="eye-pulse" style="transform-origin: 466px 101px;">
      <ellipse cx="466" cy="101" rx="11" ry="6" fill="url(#eyeGlowCore)" filter="url(#eyeFlare)" />
      <polygon points="460,103 469,99 473,101 465,104" fill="#FFF" opacity="0.9" />
    </g>

    <!-- Right Eye Glowing Iris & Laser Aura -->
    <g class="eye-pulse" style="transform-origin: 494px 101px;">
      <ellipse cx="494" cy="101" rx="11" ry="6" fill="url(#eyeGlowCore)" filter="url(#eyeFlare)" />
      <polygon points="487,101 491,99 500,103 495,104" fill="#FFF" opacity="0.9" />
    </g>

    <!-- Forehead Horn Crest Ambient Ember Flare -->
    <circle cx="480" cy="74" r="4.5" fill="#FF2B3C" opacity="0.85" filter="url(#eyeFlare)" />
  </g>

  <!-- Product Title: ANDHAK EDR -->
  <g class="title-anim">
    <text x="480" y="206" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif" font-size="36" font-weight="900" fill="url(#titleGrad)" letter-spacing="0.22em">ANDHAK EDR</text>
  </g>

  <!-- Tagline: DETECT · INVESTIGATE · RESPOND -->
  <text x="480" y="236" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="700" fill="#94A3B8" letter-spacing="0.34em">DETECT  ·  INVESTIGATE  ·  RESPOND</text>

  <!-- Subtle Divider Line -->
  <line x1="280" y1="256" x2="680" y2="256" stroke="#1E293B" stroke-width="1" />
  <circle cx="480" cy="256" r="2.5" fill="#A92532" />

  <!-- Animated Telemetry Badges / Operational Indicators -->
  <g transform="translate(180, 274)" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="10.5" font-weight="600">
    <!-- Rust Sensor Active -->
    <g transform="translate(0, 0)">
      <rect x="0" y="0" width="138" height="22" rx="4" fill="#0F172A" stroke="#1E293B" stroke-width="1" />
      <circle class="led-green" cx="12" cy="11" r="3.5" fill="#10B981" />
      <text x="24" y="15" fill="#E2E8F0">RUST SENSOR</text>
    </g>

    <!-- Deterministic Engine -->
    <g transform="translate(148, 0)">
      <rect x="0" y="0" width="148" height="22" rx="4" fill="#0F172A" stroke="#1E293B" stroke-width="1" />
      <circle class="led-red" cx="12" cy="11" r="3.5" fill="#EF4444" />
      <text x="24" y="15" fill="#E2E8F0">ZERO-AI ENGINE</text>
    </g>

    <!-- Forensic Chain -->
    <g transform="translate(306, 0)">
      <rect x="0" y="0" width="144" height="22" rx="4" fill="#0F172A" stroke="#1E293B" stroke-width="1" />
      <circle class="led-cyan" cx="12" cy="11" r="3.5" fill="#06B6D4" />
      <text x="24" y="15" fill="#E2E8F0">SHA-256 AUDIT</text>
    </g>

    <!-- SOC Connected -->
    <g transform="translate(460, 0)">
      <rect x="0" y="0" width="140" height="22" rx="4" fill="#0F172A" stroke="#1E293B" stroke-width="1" />
      <circle class="led-amber" cx="12" cy="11" r="3.5" fill="#F59E0B" />
      <text x="24" y="15" fill="#E2E8F0">SOC COMPANION</text>
    </g>
  </g>
</svg>
"""

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"Generated {out_path} ({len(svg_content)} bytes)")

if __name__ == "__main__":
    generate_banner()
