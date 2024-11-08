import { isString } from 'lodash';

import {
  type PluginExtension,
  PluginExtensionTypes,
  type PluginExtensionLink,
  type PluginExtensionLinkConfig,
  type PluginExtensionComponent,
  urlUtil,
} from '@grafana/data';
import { GetPluginExtensions, reportInteraction } from '@grafana/runtime';

import { ReactivePluginExtensionsRegistry } from './reactivePluginExtensionRegistry';
import { AddedComponentsRegistry } from './registry/AddedComponentsRegistry';
import type { AddedComponentsRegistryState, PluginExtensionRegistry } from './types';
import {
  isPluginExtensionLinkConfig,
  getReadOnlyProxy,
  logWarning,
  generateExtensionId,
  getEventHelpers,
  wrapWithPluginContext,
} from './utils';
import { assertIsNotPromise, assertLinkPathIsValid, assertStringProps, isPromise } from './validators';

type GetExtensions = ({
  context,
  extensionPointId,
  limitPerPlugin,
  registry,
  addedComponentsRegistry,
}: {
  context?: object | Record<string | symbol, unknown>;
  extensionPointId: string;
  limitPerPlugin?: number;
  registry: PluginExtensionRegistry;
  addedComponentsRegistry: AddedComponentsRegistryState;
}) => { extensions: PluginExtension[] };

export function createPluginExtensionsGetter(
  extensionRegistry: ReactivePluginExtensionsRegistry,
  addedComponentRegistry: AddedComponentsRegistry
): GetPluginExtensions {
  let registry: PluginExtensionRegistry = { id: '', extensions: {} };
  let addedComponentsRegistryState: AddedComponentsRegistryState = {};

  // Create a subscription to keep an copy of the registry state for use in the non-async
  // plugin extensions getter.
  extensionRegistry.asObservable().subscribe((r) => {
    registry = r;
  });

  addedComponentRegistry.asObservable().subscribe((r) => {
    addedComponentsRegistryState = r;
  });

  return (options) =>
    getPluginExtensions({ ...options, registry, addedComponentsRegistry: addedComponentsRegistryState });
}

// Returns with a list of plugin extensions for the given extension point
export const getPluginExtensions: GetExtensions = ({
  context,
  extensionPointId,
  limitPerPlugin,
  registry,
  addedComponentsRegistry,
}) => {
  const frozenContext = context ? getReadOnlyProxy(context) : {};
  const registryItems = registry.extensions[extensionPointId] ?? [];
  // We don't return the extensions separated by type, because in that case it would be much harder to define a sort-order for them.
  const extensions: PluginExtension[] = [];
  const extensionsByPlugin: Record<string, number> = {};

  for (const registryItem of registryItems) {
    try {
      const extensionConfig = registryItem.config;
      const { pluginId } = registryItem;

      // Only limit if the `limitPerPlugin` is set
      if (limitPerPlugin && extensionsByPlugin[pluginId] >= limitPerPlugin) {
        continue;
      }

      if (extensionsByPlugin[pluginId] === undefined) {
        extensionsByPlugin[pluginId] = 0;
      }

      // LINK
      if (isPluginExtensionLinkConfig(extensionConfig)) {
        // Run the configure() function with the current context, and apply the ovverides
        const overrides = getLinkExtensionOverrides(pluginId, extensionConfig, frozenContext);

        // configure() returned an `undefined` -> hide the extension
        if (extensionConfig.configure && overrides === undefined) {
          continue;
        }

        const path = overrides?.path || extensionConfig.path;
        const extension: PluginExtensionLink = {
          id: generateExtensionId(pluginId, extensionConfig),
          type: PluginExtensionTypes.link,
          pluginId: pluginId,
          onClick: getLinkExtensionOnClick(pluginId, extensionConfig, frozenContext),

          // Configurable properties
          icon: overrides?.icon || extensionConfig.icon,
          title: overrides?.title || extensionConfig.title,
          description: overrides?.description || extensionConfig.description,
          path: isString(path) ? getLinkExtensionPathWithTracking(pluginId, path, extensionConfig) : undefined,
          category: overrides?.category || extensionConfig.category,
        };

        extensions.push(extension);
        extensionsByPlugin[pluginId] += 1;
      }
    } catch (error) {
      if (error instanceof Error) {
        logWarning(error.message);
      }
    }
  }

  if (extensionPointId in addedComponentsRegistry) {
    try {
      const addedComponents = addedComponentsRegistry[extensionPointId];
      for (const addedComponent of addedComponents) {
        // Only limit if the `limitPerPlugin` is set
        if (limitPerPlugin && extensionsByPlugin[addedComponent.pluginId] >= limitPerPlugin) {
          continue;
        }

        if (extensionsByPlugin[addedComponent.pluginId] === undefined) {
          extensionsByPlugin[addedComponent.pluginId] = 0;
        }
        const extension: PluginExtensionComponent = {
          id: generateExtensionId(addedComponent.pluginId, {
            ...addedComponent,
            extensionPointId,
            type: PluginExtensionTypes.component,
          }),
          type: PluginExtensionTypes.component,
          pluginId: addedComponent.pluginId,
          title: addedComponent.title,
          description: addedComponent.description,
          component: wrapWithPluginContext(addedComponent.pluginId, addedComponent.component),
        };

        extensions.push(extension);
        extensionsByPlugin[addedComponent.pluginId] += 1;
      }
    } catch (error) {
      if (error instanceof Error) {
        logWarning(error.message);
      }
    }
  }

  return { extensions };
};

function getLinkExtensionOverrides(pluginId: string, config: PluginExtensionLinkConfig, context?: object) {
  try {
    const overrides = config.configure?.(context);

    // Hiding the extension
    if (overrides === undefined) {
      return undefined;
    }

    let {
      title = config.title,
      description = config.description,
      path = config.path,
      icon = config.icon,
      category = config.category,
      ...rest
    } = overrides;

    assertIsNotPromise(
      overrides,
      `The configure() function for "${config.title}" returned a promise, skipping updates.`
    );

    path && assertLinkPathIsValid(pluginId, path);
    assertStringProps({ title, description }, ['title', 'description']);

    if (Object.keys(rest).length > 0) {
      logWarning(
        `Extension "${config.title}", is trying to override restricted properties: ${Object.keys(rest).join(
          ', '
        )} which will be ignored.`
      );
    }

    return {
      title,
      description,
      path,
      icon,
      category,
    };
  } catch (error) {
    if (error instanceof Error) {
      logWarning(error.message);
    }

    // If there is an error, we hide the extension
    // (This seems to be safest option in case the extension is doing something wrong.)
    return undefined;
  }
}

function getLinkExtensionOnClick(
  pluginId: string,
  config: PluginExtensionLinkConfig,
  context?: object
): ((event?: React.MouseEvent) => void) | undefined {
  const { onClick } = config;

  if (!onClick) {
    return;
  }

  return function onClickExtensionLink(event?: React.MouseEvent) {
    try {
      reportInteraction('ui_extension_link_clicked', {
        pluginId: pluginId,
        extensionPointId: config.extensionPointId,
        title: config.title,
        category: config.category,
      });

      const result = onClick(event, getEventHelpers(pluginId, context));

      if (isPromise(result)) {
        result.catch((e) => {
          if (e instanceof Error) {
            logWarning(e.message);
          }
        });
      }
    } catch (error) {
      if (error instanceof Error) {
        logWarning(error.message);
      }
    }
  };
}

function getLinkExtensionPathWithTracking(pluginId: string, path: string, config: PluginExtensionLinkConfig): string {
  return urlUtil.appendQueryToUrl(
    path,
    urlUtil.toUrlParams({
      uel_pid: pluginId,
      uel_epid: config.extensionPointId,
    })
  );
}
