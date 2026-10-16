import React, { useRef, useEffect } from 'react';

export default function Waveform({ historyDl, historyUl, totals, activeSockets }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = rect.height;

    ctx.clearRect(0, 0, width, height);

    // Subtle horizontal guidelines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    for (let y = 0.25; y < 1; y += 0.25) {
      ctx.beginPath();
      ctx.moveTo(0, height * y);
      ctx.lineTo(width, height * y);
      ctx.stroke();
    }

    const maxVal = Math.max(8192, ...historyDl, ...historyUl) * 1.15;
    const step = width / (historyDl.length - 1);

    function renderCurve(data, strokeColor, fillColor) {
      if (data.length < 2) return;
      ctx.beginPath();
      ctx.moveTo(0, height);

      for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const norm = Math.min(data[i] / maxVal, 1);
        const y = height - (norm * (height - 6));
        if (i === 0) {
          ctx.lineTo(x, y);
        } else {
          const prevX = (i - 1) * step;
          const prevY = height - (Math.min(data[i - 1] / maxVal, 1) * (height - 6));
          const cx = (prevX + x) / 2;
          ctx.bezierCurveTo(cx, prevY, cx, y, x, y);
        }
      }

      ctx.lineTo(width, height);
      ctx.closePath();
      ctx.fillStyle = fillColor;
      ctx.fill();

      // Stroke line
      ctx.beginPath();
      for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const norm = Math.min(data[i] / maxVal, 1);
        const y = height - (norm * (height - 6));
        if (i === 0) {
          ctx.moveTo(x, y);
        } else {
          const prevX = (i - 1) * step;
          const prevY = height - (Math.min(data[i - 1] / maxVal, 1) * (height - 6));
          const cx = (prevX + x) / 2;
          ctx.bezierCurveTo(cx, prevY, cx, y, x, y);
        }
      }
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // Download Area (Cyan)
    const dlGrad = ctx.createLinearGradient(0, 0, 0, height);
    dlGrad.addColorStop(0, 'rgba(0, 242, 254, 0.28)');
    dlGrad.addColorStop(1, 'rgba(0, 242, 254, 0.0)');
    renderCurve(historyDl, '#00f2fe', dlGrad);

    // Upload Area (Purple)
    const ulGrad = ctx.createLinearGradient(0, 0, 0, height);
    ulGrad.addColorStop(0, 'rgba(192, 132, 252, 0.24)');
    ulGrad.addColorStop(1, 'rgba(192, 132, 252, 0.0)');
    renderCurve(historyUl, '#c084fc', ulGrad);

    // Scale label
    ctx.fillStyle = 'rgba(100, 116, 139, 0.6)';
    ctx.font = '10px JetBrains Mono, monospace';
    const scaleText = maxVal >= 1048576 
      ? `${(maxVal / 1048576).toFixed(1)} MB/s`
      : `${(maxVal / 1024).toFixed(0)} KB/s`;
    ctx.fillText(scaleText, 6, 12);
  }, [historyDl, historyUl]);

  return (
    <section className="waveform-hero">
      <div className="hero-top">
        <div className="hero-title-wrap">
          <span className="hero-title">Live Bandwidth Stream</span>
          <span className="hero-subtitle">60s Telemetry Oscilloscope</span>
        </div>
        <div className="hero-metrics">
          <div className="hero-metric">
            <span className="h-label">Peak DL</span>
            <span className="h-val cyan-text">{totals.peakDlFormatted || '0 B/s'}</span>
          </div>
          <div className="hero-metric">
            <span className="h-label">Peak UL</span>
            <span className="h-val purple-text">{totals.peakUlFormatted || '0 B/s'}</span>
          </div>
          <div className="hero-metric">
            <span className="h-label">Transferred</span>
            <span className="h-val">{totals.cumulativeDlFormatted || '0 B'}</span>
          </div>
          <div className="hero-metric">
            <span className="h-label">Sockets</span>
            <span className="h-val">{activeSockets || 0}</span>
          </div>
        </div>
      </div>

      <div className="canvas-wrap">
        <canvas ref={canvasRef} id="waveCanvas" style={{ width: '100%', height: '90px' }} />
      </div>
    </section>
  );
}
