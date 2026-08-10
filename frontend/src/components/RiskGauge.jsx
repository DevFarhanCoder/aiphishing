import React, { useEffect, useState } from "react";

/**
 * Half-circle SVG risk gauge. Animates from 0 to the target score on mount /
 * whenever `score` changes. Color is driven by risk level.
 */
const LEVEL_COLOR = {
  Safe: "#00E676",
  "Low Risk": "#00E5FF",
  "Medium Risk": "#FFD700",
  "High Risk": "#FF9900",
  Critical: "#FF3366",
};

export const RiskGauge = ({ score = 0, level = "Safe" }) => {
  const [animated, setAnimated] = useState(0);
  const color = LEVEL_COLOR[level] || "#00E5FF";

  useEffect(() => {
    let raf;
    const start = performance.now();
    const from = animated;
    const to = Math.max(0, Math.min(100, score));
    const duration = 900;
    const step = (t) => {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setAnimated(Math.round(from + (to - from) * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [score]);

  // Half-circle geometry
  const size = 260;
  const stroke = 18;
  const radius = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = Math.PI * radius; // half
  const dash = (animated / 100) * circumference;

  return (
    <div className="flex flex-col items-center" data-testid="risk-gauge">
      <svg width={size} height={size / 2 + 24} viewBox={`0 0 ${size} ${size / 2 + 24}`}>
        {/* Track */}
        <path
          d={`M ${stroke / 2} ${cy} A ${radius} ${radius} 0 0 1 ${size - stroke / 2} ${cy}`}
          stroke="rgba(30,41,59,0.9)"
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
        />
        {/* Value */}
        <path
          d={`M ${stroke / 2} ${cy} A ${radius} ${radius} 0 0 1 ${size - stroke / 2} ${cy}`}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          style={{ filter: `drop-shadow(0 0 6px ${color}66)` }}
        />
        <text
          x={cx}
          y={cy - 8}
          textAnchor="middle"
          fontFamily='"JetBrains Mono", monospace'
          fontWeight="600"
          fontSize="48"
          fill="#F8FAFC"
          data-testid="risk-gauge-value"
        >
          {animated}
          <tspan fontSize="22" fill={color}>%</tspan>
        </text>
        <text
          x={cx}
          y={cy + 18}
          textAnchor="middle"
          fontFamily='"IBM Plex Sans", sans-serif'
          fontSize="11"
          letterSpacing="4"
          fill={color}
          data-testid="risk-gauge-level"
        >
          {level.toUpperCase()}
        </text>
      </svg>
    </div>
  );
};

export default RiskGauge;
