export class ResponsePage<T> {
  count?: number;
  results?: T[];
  next?: string;
  previous?: string;
}
