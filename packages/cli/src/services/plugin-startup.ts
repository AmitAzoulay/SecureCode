import type { OpenCodeClient } from "@opencode/client"
import { Effect, Schedule } from "effect"

// Catalog reads return whatever is loaded, so one-shot commands, which read once and exit, wait until the Location
// reports its plugins have finished loading, npm installs included.
export const waitForPlugins = (client: OpenCodeClient, directory: string) =>
  Effect.tryPromise((signal) => client.experimental.plugin.ready({ location: { directory } }, { signal })).pipe(
    Effect.repeat({
      until: (result) => result.data.ready,
      schedule: Schedule.spaced("25 millis").pipe(Schedule.upTo({ duration: "5 seconds" })),
    }),
    Effect.ignore,
  )
