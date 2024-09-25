export type { MergeDeep, PickDeep, SetRequired } from 'type-fest';

export type Prettify<T> = {
  [K in keyof T]: T[K];
} & Record<string, unknown>;

export type MaybePromise<TType> = Promise<TType> | TType;
