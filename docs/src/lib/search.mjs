let searchModule
let loadAttempt = 0

export function loadSearch(basePath) {
  if (!searchModule) {
    searchModule = import(
      /* webpackIgnore: true */ `${basePath}/pagefind/pagefind.js${
        loadAttempt ? `?retry=${loadAttempt}` : ''
      }`
    )
      .then(async (pagefind) => {
        await pagefind.options({ baseUrl: `${basePath}/` })
        await pagefind.init()
        return pagefind
      })
      .catch((error) => {
        loadAttempt += 1
        searchModule = undefined
        throw error
      })
  }
  return searchModule
}

export function resetSearch() {
  loadAttempt += 1
  searchModule = undefined
}

export function excerptText(encoded) {
  const decoder = document.createElement('textarea')
  decoder.innerHTML = encoded
  return decoder.value
}

export function bestSection(result) {
  const sections = result.sub_results ?? []
  const score = (section) =>
    (section.weighted_locations ?? []).reduce(
      (total, location) => total + location.balanced_score,
      0
    )
  return sections.reduce(
    (best, section) => (!best || score(section) > score(best) ? section : best),
    undefined
  )
}
