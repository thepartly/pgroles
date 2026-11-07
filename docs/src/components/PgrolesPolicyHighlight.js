import { isMap, isScalar, isSeq, parseDocument } from 'yaml'
import manifestMetadata from '../../public/generated/manifest-metadata.json' with { type: 'json' }

const manifestSchema = manifestMetadata.manifest_schema
const fieldNotes = {
  exclusive: 'Additive mode skips revocations; ordinary cloud-provider management roles are not exempt from exclusivity.',
}

const roleReferenceFields = new Set([
  'default_owner',
  'role_pattern',
  'owner',
  'role',
  'reassign_owned_to',
])
function addRange(ranges, node, className, title) {
  if (!node?.range) return
  ranges.push({
    start: node.range[0],
    end: node.range[1],
    className,
    title,
  })
}

function dereference(schema) {
  let resolved = schema
  const seen = new Set()
  while (resolved?.$ref?.startsWith('#/') && !seen.has(resolved.$ref)) {
    seen.add(resolved.$ref)
    resolved = resolved.$ref
      .slice(2)
      .split('/')
      .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
      .reduce((value, segment) => value?.[segment], manifestSchema)
  }
  return resolved ?? schema
}

function scalarField(map, key) {
  return map?.items.find(
    (pair) => isScalar(pair.key) && pair.key.value === key && isScalar(pair.value)
  )?.value?.value
}

function acceptsDiscriminator(schema, value) {
  const resolved = dereference(schema)
  const type = resolved?.properties?.type
  return type?.const === value || type?.enum?.includes(value)
}

function schemaBranches(schema, parent) {
  const resolved = dereference(schema)
  if (!resolved || typeof resolved !== 'object') return []
  const allOf = resolved.allOf ?? []
  const alternatives = [...(resolved.anyOf ?? []), ...(resolved.oneOf ?? [])]
  if (alternatives.length === 0) return [resolved, ...allOf.flatMap((item) => schemaBranches(item, parent))]

  const discriminator = scalarField(parent, 'type')
  const discriminated = alternatives.some((item) => {
    const type = dereference(item)?.properties?.type
    return type && (Object.hasOwn(type, 'const') || Array.isArray(type.enum))
  })
  const selected = discriminator === undefined || !discriminated
    ? alternatives
    : alternatives.filter((item) => acceptsDiscriminator(item, discriminator))
  const discriminatorOnly = discriminated && selected.length === 0
    ? alternatives.map((item) => ({ properties: { type: dereference(item)?.properties?.type } }))
    : []
  return [resolved, ...allOf.flatMap((item) => schemaBranches(item, parent)), ...selected.flatMap((item) => schemaBranches(item, parent)), ...discriminatorOnly]
}

function fieldForKey(schema, key, parent) {
  for (const branch of schemaBranches(schema, parent)) {
    const properties = branch.properties ?? {}
    if (Object.hasOwn(properties, key)) {
      return { schema: properties[key], canonical: key, alias: false, dynamic: false }
    }
    for (const [canonical, property] of Object.entries(properties)) {
      if (property['x-serde-aliases']?.includes(key)) {
        return { schema: property, canonical, alias: true, dynamic: false }
      }
    }
  }
  for (const branch of schemaBranches(schema, parent)) {
    if (branch.additionalProperties && branch.additionalProperties !== true) {
      return { schema: branch.additionalProperties, canonical: key, alias: false, dynamic: true }
    }
  }
  return null
}

function keyDecoration(key, schema, parent, path) {
  const field = fieldForKey(schema, key, parent)
  if (!field) {
    return {
      className: 'pgroles-unrecognized',
      title: 'Unrecognized field. pgroles currently ignores unknown YAML keys.',
      recognized: false,
    }
  }
  if (field.dynamic) {
    return {
      className: 'pgroles-identifier',
      title: field.schema.description ?? 'Named policy entry.',
      recognized: true,
      field,
    }
  }
  if (field.alias) {
    return {
      className: 'pgroles-deprecated',
      title: `Legacy alias. Prefer the canonical ${field.canonical} field.`,
      recognized: true,
      field,
    }
  }
  return {
    className: path.length === 0 ? 'pgroles-section' : 'pgroles-field',
    title: [field.schema.description ?? `Recognized pgroles field: ${key}`, fieldNotes[key]].filter(Boolean).join(' '),
    recognized: true,
    field,
  }
}

function valueDecoration(key, path) {
  if (key === 'privileges') {
    return {
      className: 'pgroles-privilege',
      title: 'PostgreSQL privilege managed by this policy.',
    }
  }
  if (key === 'type' || key === 'on_type' || key === 'ensure') {
    return {
      className: 'pgroles-enum',
      title: 'pgroles object or provider type.',
    }
  }
  if (roleReferenceFields.has(key)) {
    return {
      className: 'pgroles-role-ref',
      title: 'PostgreSQL role reference.',
    }
  }
  if (key === 'schema') {
    return {
      className: 'pgroles-schema-ref',
      title: 'PostgreSQL schema reference.',
    }
  }
  if (key === 'profiles') {
    return {
      className: 'pgroles-profile-ref',
      title: 'Reusable pgroles profile reference.',
    }
  }

  if (key === 'name') {
    if (path[0] === 'roles' || path[0] === 'memberships') {
      return {
        className: 'pgroles-role-ref',
        title: 'PostgreSQL role name.',
      }
    }
    if (path[0] === 'schemas') {
      return {
        className: 'pgroles-schema-ref',
        title: 'PostgreSQL schema name.',
      }
    }
    if (
      path[0] === 'grants' ||
      (path[0] === 'profiles' && path.includes('object'))
    ) {
      return {
        className: 'pgroles-object-ref',
        title: 'PostgreSQL object name.',
      }
    }
  }

  return null
}

function addScalarValues(ranges, node, decoration) {
  if (!decoration || !node) return
  if (isScalar(node)) {
    addRange(ranges, node, decoration.className, decoration.title)
    return
  }
  if (isSeq(node)) {
    node.items.forEach((item) => addScalarValues(ranges, item, decoration))
  }
}

function walkNode(ranges, node, schema = manifestSchema, path = []) {
  if (isMap(node)) {
    node.items.forEach((pair) => {
      const key = isScalar(pair.key) ? String(pair.key.value) : null
      if (!key) return

      const keyStyle = keyDecoration(key, schema, node, path)
      addRange(ranges, pair.key, keyStyle.className, keyStyle.title)
      if (keyStyle.recognized) {
        addScalarValues(ranges, pair.value, valueDecoration(keyStyle.field.canonical, path))
      }
      walkNode(ranges, pair.value, keyStyle.field?.schema ?? {}, [...path, key])
    })
    return
  }

  if (isSeq(node)) {
    const itemSchema = dereference(schema)?.items ?? {}
    node.items.forEach((item) => walkNode(ranges, item, itemSchema, [...path, '*']))
  }
}

export function getPgrolesSemanticRanges(code) {
  const document = parseDocument(code, { keepSourceTokens: true })
  const ranges = []

  if (document.contents) walkNode(ranges, document.contents)

  return {
    ranges: ranges.sort((left, right) => left.start - right.start),
    errors: document.errors.map((error) => error.message),
  }
}

export function splitSemanticToken(token, start, ranges) {
  const end = start + token.content.length
  const overlaps = ranges.filter(
    (range) => range.start < end && range.end > start
  )
  if (overlaps.length === 0) return [{ token, start }]

  const boundaries = new Set([start, end])
  overlaps.forEach((range) => {
    boundaries.add(Math.max(start, range.start))
    boundaries.add(Math.min(end, range.end))
  })
  const ordered = [...boundaries].sort((left, right) => left - right)

  return ordered.slice(0, -1).map((pieceStart, index) => {
    const pieceEnd = ordered[index + 1]
    const semantic = overlaps.find(
      (range) => range.start <= pieceStart && range.end >= pieceEnd
    )

    return {
      start: pieceStart,
      token: {
        ...token,
        content: token.content.slice(pieceStart - start, pieceEnd - start),
        semanticClassName: semantic?.className,
        semanticTitle: semantic?.title,
      },
    }
  })
}
