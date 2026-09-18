export function withBasePath(basePath, href) {
  if (!href.startsWith('/') || href.startsWith('//')) {
    return href
  }

  return `${basePath}${href}`
}
