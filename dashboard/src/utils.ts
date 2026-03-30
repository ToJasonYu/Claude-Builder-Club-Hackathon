export function getScoreColor(score: number): string {
  if (score >= 80) return '#ff3b5c'
  if (score >= 60) return '#ff8c42'
  if (score >= 40) return '#ffd166'
  return '#00c896'
}

export function renderMarkdown(md: string): string {
  let html = md
  html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => `<pre><code class="language-${lang}">${code.trim()}</code></pre>`)
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>')
  html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>')
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>')
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>')
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
  html = html.replace(/^---$/gm, '<hr>')

  html = html.replace(/^\|(.+)\|$/gm, (match) => {
    const cells = match.split('|').filter(c => c.trim())
    if (cells.every(c => /^[\s-:]+$/.test(c))) return '<!-- sep -->'
    return cells.map(c => `<td>${c.trim()}</td>`).join('')
  })

  const lines = html.split('\n')
  let inTable = false
  let tableHtml = ''
  const output: string[] = []

  for (const line of lines) {
    if (line.startsWith('<td>')) {
      if (!inTable) { tableHtml = '<table><tbody>'; inTable = true }
      if (line !== '<!-- sep -->') tableHtml += `<tr>${line}</tr>`
    } else {
      if (inTable) {
        tableHtml += '</tbody></table>'
        tableHtml = tableHtml.replace(/<tbody><tr>(.*?)<\/tr>/, (_, cells) =>
          `<thead><tr>${cells.replace(/<td>/g, '<th>').replace(/<\/td>/g, '</th>')}</tr></thead><tbody>`)
        output.push(tableHtml)
        inTable = false
        tableHtml = ''
      }
      output.push(line)
    }
  }
  if (inTable) {
    tableHtml += '</tbody></table>'
    tableHtml = tableHtml.replace(/<tbody><tr>(.*?)<\/tr>/, (_, cells) =>
      `<thead><tr>${cells.replace(/<td>/g, '<th>').replace(/<\/td>/g, '</th>')}</tr></thead><tbody>`)
    output.push(tableHtml)
  }

  html = output.join('\n')
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>')
  html = html.replace(/(<li>.*<\/li>\n?)+/g, (match) => `<ul>${match}</ul>`)
  html = html.replace(/^(?!<[a-z]|$)(.+)$/gm, '<p>$1</p>')
  html = html.replace(/<\/blockquote>\n<blockquote>/g, '<br>')

  return html
}
