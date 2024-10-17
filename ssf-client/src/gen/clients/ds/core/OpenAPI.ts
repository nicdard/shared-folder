// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
import type { AxiosRequestConfig, AxiosResponse } from 'axios';
import type { ApiRequestOptions } from './ApiRequestOptions';

type Headers = Record<string, string>;
type Middleware<T> = (value: T) => T | Promise<T>;
type Resolver<T> = (options: ApiRequestOptions) => Promise<T>;

export class Interceptors<T> {
  _fns: Middleware<T>[];

  constructor() {
    this._fns = [];
  }

  eject(fn: Middleware<T>) {
    const index = this._fns.indexOf(fn);
    if (index !== -1) {
      this._fns = [...this._fns.slice(0, index), ...this._fns.slice(index + 1)];
    }
  }

  use(fn: Middleware<T>) {
    this._fns = [...this._fns, fn];
  }
}

export type OpenAPIConfig = {
  BASE: string;
  CREDENTIALS: 'include' | 'omit' | 'same-origin';
  ENCODE_PATH?: ((path: string) => string) | undefined;
  HEADERS?: Headers | Resolver<Headers> | undefined;
  PASSWORD?: string | Resolver<string> | undefined;
  TOKEN?: string | Resolver<string> | undefined;
  USERNAME?: string | Resolver<string> | undefined;
  VERSION: string;
  WITH_CREDENTIALS: boolean;
  interceptors: {
    request: Interceptors<AxiosRequestConfig>;
    response: Interceptors<AxiosResponse>;
  };
};

export const OpenAPI: OpenAPIConfig = {
  BASE: 'https://localhost:8001',
  CREDENTIALS: 'include',
  ENCODE_PATH: undefined,
  HEADERS: undefined,
  PASSWORD: undefined,
  TOKEN: undefined,
  USERNAME: undefined,
  VERSION: '0.1.0',
  WITH_CREDENTIALS: false,
  interceptors: {
    request: new Interceptors(),
    response: new Interceptors(),
  },
};
