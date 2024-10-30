import { DataItem } from '../cbor/data-item.js';
import { cborDecode } from '../cbor/index.js';
import type { DeviceRequestNameSpaces } from './model/device-request.js';

export interface ItemsRequestData {
  docType: string;
  nameSpaces: DeviceRequestNameSpaces;
  requestInfo?: Record<string, unknown>;
}

export type ItemsRequestDataItem = DataItem<ItemsRequestData>;

export class ItemsRequest {
  #dataRecord?: ItemsRequestData;
  readonly #dataItem: ItemsRequestDataItem;

  constructor(dataItem: ItemsRequestDataItem) {
    this.#dataItem = dataItem;
  }

  public get dataItem() {
    return this.#dataItem;
  }

  public get data(): ItemsRequestData {
    if (!this.#dataRecord) {
      this.#dataRecord = cborDecode(this.#dataItem.buffer, {
        tagUint8Array: false,
        useRecords: true,
        mapsAsObjects: true,
      }) as ItemsRequestData;
    }

    return this.#dataRecord;
  }

  public static create(
    docType: string,
    nameSpaces: DeviceRequestNameSpaces,
    requestInfo?: Record<string, unknown>
  ): ItemsRequest {
    const dataItem = DataItem.fromData({
      docType,
      nameSpaces,
      requestInfo,
    }) as unknown as ItemsRequestDataItem;
    return new ItemsRequest(dataItem);
  }
}
