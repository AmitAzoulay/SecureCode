export * as FileWrite from "./file-write.js"

import { makeLocationNode } from "@opencode/util/effect/app-node"
import type { FileDiff } from "@opencode/schema/file-diff"
import { Bom } from "@opencode/util/bom"
import { Context, Effect, Layer } from "effect"
import { Environment } from "./environment/index.js"
import { FileAccess } from "./file-access.js"
import { FileMutation } from "./file-mutation.js"
import { Formatter } from "./formatter.js"
import { Location } from "./location.js" // <-- CHANGE 1: Add Location import
import { Permission } from "./permission.js"
import type { SessionErrors } from "./session/error.js"
import { fileDiff } from "./tool/plugin/file-diff.js"
import { Win32Sandbox } from "./win32-sandbox.js" // <-- CHANGE 1: Add Win32Sandbox import

export interface WriteInput {
  readonly path: string
  readonly content: string
}

export interface Written extends FileMutation.TextWriteResult {
  /** The file text after a formatter ran on it. */
  readonly formatted?: string
}

export interface Interface {
  /** Resolve a file to write and enforce session-directory confinement. */
  readonly target: (
    file: string,
    context: FileAccess.Invocation,
  ) => Effect.Effect<FileAccess.Target, Environment.Failed | Permission.Error | SessionErrors.NotFoundError>
  /** Request edit approval for a resolved target, showing the change when it is known. */
  readonly authorize: (
    target: FileAccess.Target,
    context: FileAccess.Invocation,
    preview?: FileDiff.Info,
  ) => Effect.Effect<void, Permission.Error | SessionErrors.NotFoundError>
  /** Write approved text, keeping an existing UTF-8 BOM, then format the file. */
  readonly commit: (
    target: FileAccess.Target,
    content: string,
  ) => Effect.Effect<Written, Environment.NotFound | Environment.WrongKind | Environment.Failed>
  /** Resolve, approve, write and format a whole file. */
  readonly write: (
    input: WriteInput,
    context: FileAccess.Invocation,
  ) => Effect.Effect<
    Written,
    Environment.NotFound | Environment.WrongKind | Environment.Failed | Permission.Error | SessionErrors.NotFoundError
  >
}

export class Service extends Context.Service<Service, Interface>()("@opencode/FileWrite") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const access = yield* FileAccess.Service
    const environment = yield* Environment.Service
    const fileMutation = yield* FileMutation.Service
    const formatter = yield* Formatter.Service
    const location = yield* Location.Service // <-- CHANGE 2: Yield Location.Service
    const permission = yield* Permission.Service

    // <-- CHANGE 3: Replace authorizeExternal() with hard OS-level confinement check
    const target = Effect.fn("FileWrite.target")(function* (file: string, context: FileAccess.Invocation) {
      const resolved = yield* access.resolve({ path: file, kind: "file" })
      if (resolved.externalDirectory) {
        if (process.platform === "win32") {
          yield* Effect.try({
            try: () => Win32Sandbox.writeFileRestrictedSync(location.directory, resolved.absolute, new Uint8Array(0)),
            catch: (err) =>
              new Environment.Failed({
                path: resolved.absolute,
                cause: err,
              }),
          })
        }
        return yield* new Environment.Failed({
          path: resolved.absolute,
          cause: new Error(`[OS Confinement] Write denied outside session directory (${location.directory})`),
        })
      }
      return resolved
    })

    const authorize = Effect.fn("FileWrite.authorize")(function* (
      target: FileAccess.Target,
      context: FileAccess.Invocation,
      preview?: FileDiff.Info,
    ) {
      yield* permission.assert({
        action: "edit",
        resources: [target.resource],
        save: ["*"],
        metadata: preview ? { files: [preview] } : undefined,
        ...Permission.invocation(context),
      })
    })

    const commit = Effect.fn("FileWrite.commit")(function* (target: FileAccess.Target, content: string) {
      const written = yield* fileMutation.writeTextPreservingBom({ target, content })
      if (!(yield* formatter.file(target.absolute))) return written
      return {
        ...written,
        formatted: yield* FileMutation.syncTextBom(environment.files, target.absolute, written.bom),
      } satisfies Written
    })

    const write = Effect.fn("FileWrite.write")(function* (input: WriteInput, context: FileAccess.Invocation) {
      const resolved = yield* target(input.path, context)
      const current = yield* FileMutation.readOptionalText(environment.files, resolved.absolute)
      yield* authorize(
        resolved,
        context,
        fileDiff(resolved.resource, current?.text ?? "", Bom.split(input.content).text, current ? "modified" : "added"),
      )
      return yield* commit(resolved, input.content)
    })

    return Service.of({ target, authorize, commit, write })
  }),
)

export const node = makeLocationNode({
  service: Service,
  layer,
  // <-- CHANGE 4: Add Location.node to deps
  deps: [Environment.node, FileAccess.node, FileMutation.node, Formatter.node, Location.node, Permission.node],
})