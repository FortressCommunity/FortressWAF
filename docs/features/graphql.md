# GraphQL Protection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides specialized protection for GraphQL APIs, addressing query complexity attacks, introspection leaks, and batch abuse.

## Configuration

```yaml
graphql:
  enabled: true
  max_depth: 10              # Maximum query nesting depth
  max_cost: 1000             # Maximum query cost score
  max_aliases: 15            # Maximum field aliases per query
  max_batch_size: 1          # Maximum queries per batch request
  max_tokens: 10000          # Maximum query length in characters
  block_introspection: true  # Block __schema / __type queries
  block_schema: true         # Block __typename introspection
  strict_validation: true    # Block malformed JSON requests
  allowed_operations:        # Allowed operation types
    - query
    - mutation
  restricted_fields: []      # Blocked field patterns
```

## Query Depth Limiting

Prevents deeply nested queries that could exhaust server resources:

```graphql
# Blocked if max_depth = 3
query {
  user {
    posts {
      comments {
        author {     # depth 4 - blocked
          profile {
            avatar
          }
        }
      }
    }
  }
}
```

## Query Cost Analysis

Each query element has a cost value. Requests exceeding `max_cost` are blocked:

| Element | Cost |
|---------|------|
| `query` | 1 |
| `mutation` | 10 |
| `subscription` | 100 |
| `fragment` | 5 |
| `... on` (inline fragment) | 20 |
| `@include` / `@skip` directive | 2 |
| Pagination (`first:` N) | N² |

## Alias & Batch Control

Prevents abuse through aliases and batched queries:

```graphql
# Blocked if max_aliases = 2
query {
  a: user(id: 1) { name }
  b: user(id: 2) { name }
  c: user(id: 3) { name }  # 3rd alias - blocked
}
```

## Introspection Blocking

When enabled, blocks queries containing `__schema`, `__type`, or `IntrospectionQuery` patterns. This prevents attackers from mapping your entire schema in production.

## Validation Rules

Malformed or dangerous queries are detected:

| Rule | Pattern | Severity |
|------|---------|----------|
| Template Injection | `${`, `{{` | Critical |
| Path Traversal | `__dirname`, `__filename` | High |
| Code Execution | `eval(`, `require(`, `import(` | Critical |
| Process Access | `process` | High |

## Example: Production Configuration

```yaml
graphql:
  enabled: true
  max_depth: 8
  max_cost: 500
  max_aliases: 10
  max_batch_size: 1
  block_introspection: true
  block_schema: true
  strict_validation: true
  allowed_operations:
    - query
    - mutation
```
