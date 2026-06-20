/**
 * Round visualization: Serpent-256 (32 rounds) vs AES (10/12/14 rounds).
 * Animated SVG showing attack frontiers and security margins.
 */

interface CipherVis {
  name: string;
  totalRounds: number;
  attackFrontier: number;
  attackLabel: string;
  color: string;
  marginColor: string;
}

const ciphers: CipherVis[] = [
  {
    name: 'Serpent-256',
    totalRounds: 32,
    attackFrontier: 12,
    attackLabel: 'Best known attack: 12 rounds',
    color: '#d4a72c',
    marginColor: '#2d6a4f',
  },
  {
    name: 'AES-128',
    totalRounds: 10,
    attackFrontier: 7,
    attackLabel: 'Best attack: 7 rounds',
    color: '#4a90d9',
    marginColor: '#2d6a4f',
  },
  {
    name: 'AES-192',
    totalRounds: 12,
    attackFrontier: 8,
    attackLabel: 'Best attack: 8 rounds',
    color: '#4a90d9',
    marginColor: '#2d6a4f',
  },
  {
    name: 'AES-256',
    totalRounds: 14,
    attackFrontier: 9,
    attackLabel: 'Best attack: 9 rounds',
    color: '#4a90d9',
    marginColor: '#2d6a4f',
  },
];

export function renderVisualization(container: HTMLElement): void {
  const draw = () => {
    container.innerHTML = '';

    // Read theme colors live so the chart adapts to light/dark mode.
    const styles = getComputedStyle(document.documentElement);
    const cssVar = (name: string, fallback: string) => styles.getPropertyValue(name).trim() || fallback;
    const textColor = cssVar('--text', '#e6edf3');
    const mutedColor = cssVar('--text-muted', '#8b949e');
    const goldColor = cssVar('--gold', '#d4a72c');

    // Fixed design width: the SVG scales to fit its container via width:100% +
    // maxWidth, so nothing clips on narrow (mobile) viewports.
    const containerWidth = 760;
    const rowHeight = 60;
    const padding = 20;
    const labelWidth = 120;
    const maxRounds = 32;
    const barAreaWidth = containerWidth - labelWidth - padding * 3;
    const blockWidth = Math.max(8, Math.floor(barAreaWidth / maxRounds) - 2);
    const blockGap = 2;
    const svgHeight = ciphers.length * (rowHeight + 20) + 140;
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('viewBox', `0 0 ${containerWidth} ${svgHeight}`);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Security margin visualization comparing Serpent-256 (32 rounds, 20 unbroken) versus AES-128 (10 rounds, 3 unbroken), AES-192 (12 rounds, 4 unbroken), and AES-256 (14 rounds, 5 unbroken). Serpent has 2.7 times the safety margin of AES-256.');
    svg.style.maxWidth = `${containerWidth}px`;
    svg.style.display = 'block';
    svg.style.margin = '0 auto';

    // Title
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    title.setAttribute('x', `${containerWidth / 2}`);
    title.setAttribute('y', '30');
    title.setAttribute('text-anchor', 'middle');
    title.setAttribute('fill', textColor);
    title.setAttribute('font-size', '18');
    title.setAttribute('font-weight', 'bold');
    title.textContent = 'Round Count & Security Margins';
    svg.appendChild(title);

    ciphers.forEach((cipher, ci) => {
      const y = 60 + ci * (rowHeight + 20);

      // Label
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', `${padding}`);
      label.setAttribute('y', `${y + rowHeight / 2 + 5}`);
      label.setAttribute('fill', textColor);
      label.setAttribute('font-size', '14');
      label.setAttribute('font-weight', 'bold');
      label.textContent = cipher.name;
      svg.appendChild(label);

      // Round blocks
      for (let r = 0; r < cipher.totalRounds; r++) {
        const bx = labelWidth + padding + r * (blockWidth + blockGap);
        const isAttacked = r < cipher.attackFrontier;
        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('x', `${bx}`);
        rect.setAttribute('y', `${y}`);
        rect.setAttribute('width', `${blockWidth}`);
        rect.setAttribute('height', `${rowHeight - 10}`);
        rect.setAttribute('rx', '3');
        rect.setAttribute('fill', isAttacked ? cipher.color : cipher.marginColor);

        if (reduceMotion) {
          rect.setAttribute('opacity', '1');
        } else {
          rect.setAttribute('opacity', '0');
          rect.style.transition = 'opacity 0.15s ease';
          // Stagger animation
          const delay = r * 30;
          setTimeout(() => rect.setAttribute('opacity', '1'), delay);
        }

        svg.appendChild(rect);
      }

      // Attack frontier line
      const frontierX = labelWidth + padding + cipher.attackFrontier * (blockWidth + blockGap) - blockGap / 2;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', `${frontierX}`);
      line.setAttribute('y1', `${y - 5}`);
      line.setAttribute('x2', `${frontierX}`);
      line.setAttribute('y2', `${y + rowHeight}`);
      line.setAttribute('stroke', '#ff4444');
      line.setAttribute('stroke-width', '2');
      line.setAttribute('stroke-dasharray', '4,3');
      svg.appendChild(line);

      // Attack label
      const atk = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      atk.setAttribute('x', `${frontierX + 5}`);
      atk.setAttribute('y', `${y - 8}`);
      atk.setAttribute('fill', '#ff6666');
      atk.setAttribute('font-size', '10');
      atk.textContent = cipher.attackLabel;
      svg.appendChild(atk);

      // Margin label
      if (cipher.totalRounds > cipher.attackFrontier) {
        const margin = cipher.totalRounds - cipher.attackFrontier;
        const pct = Math.round((margin / cipher.totalRounds) * 100);
        const midX = labelWidth + padding + ((cipher.attackFrontier + cipher.totalRounds) / 2) * (blockWidth + blockGap);
        const margin_label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        margin_label.setAttribute('x', `${midX}`);
        margin_label.setAttribute('y', `${y + rowHeight + 12}`);
        margin_label.setAttribute('text-anchor', 'middle');
        margin_label.setAttribute('fill', '#66bb6a');
        margin_label.setAttribute('font-size', '10');
        margin_label.textContent = `${margin} unbroken rounds (${pct}%)`;
        svg.appendChild(margin_label);
      }
    });

    // Legend
    const ly = svgHeight - 65;
    const legendItems = [
      { color: '#d4a72c', label: 'Attacked rounds (Serpent)' },
      { color: '#4a90d9', label: 'Attacked rounds (AES)' },
      { color: '#2d6a4f', label: 'Unbroken margin' },
      { color: '#ff4444', label: 'Attack frontier' },
    ];
    legendItems.forEach((item, i) => {
      const lx = padding + i * 200;
      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', `${lx}`);
      rect.setAttribute('y', `${ly}`);
      rect.setAttribute('width', '14');
      rect.setAttribute('height', '14');
      rect.setAttribute('rx', '2');
      rect.setAttribute('fill', item.color);
      svg.appendChild(rect);

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', `${lx + 20}`);
      text.setAttribute('y', `${ly + 12}`);
      text.setAttribute('fill', mutedColor);
      text.setAttribute('font-size', '11');
      text.textContent = item.label;
      svg.appendChild(text);
    });

    // Callout
    const callout = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    callout.setAttribute('x', `${containerWidth / 2}`);
    callout.setAttribute('y', `${svgHeight - 15}`);
    callout.setAttribute('text-anchor', 'middle');
    callout.setAttribute('fill', goldColor);
    callout.setAttribute('font-size', '13');
    callout.setAttribute('font-style', 'italic');
    callout.textContent = "Serpent's unbroken margin is 2.7\u00D7 wider than AES-256";
    svg.appendChild(callout);

    container.appendChild(svg);
  };

  draw();

  const observer = new ResizeObserver(() => draw());
  observer.observe(container);

  // Redraw when the theme changes so SVG text colors stay readable.
  const themeObserver = new MutationObserver(() => draw());
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
}
