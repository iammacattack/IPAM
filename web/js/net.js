// Minimal IPv4 arithmetic for the builder (the server remains the authority on layout).

export function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc * 256) + Number(o), 0) >>> 0;
}

export function intToIp(n) {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

export function parseCidr(cidr) {
  const [ip, p] = cidr.split('/');
  return { net: ipToInt(ip), prefix: Number(p) };
}

export function cidr(net, prefix) {
  return `${intToIp(net >>> 0)}/${prefix}`;
}

export function size(prefix) {
  return 2 ** (32 - prefix);
}

/** The aligned network of `prefix` that contains `c`. */
export function supernet(c, prefix) {
  const { net } = parseCidr(c);
  const s = size(prefix);
  return cidr(Math.floor(net / s) * s, prefix);
}

export function overlaps(a, b) {
  const A = parseCidr(a), B = parseCidr(b);
  const aEnd = A.net + size(A.prefix) - 1, bEnd = B.net + size(B.prefix) - 1;
  return A.net <= bEnd && B.net <= aEnd;
}

export function contains(outer, inner) {
  const O = parseCidr(outer), I = parseCidr(inner);
  return O.prefix <= I.prefix && I.net >= O.net && I.net + size(I.prefix) <= O.net + size(O.prefix);
}

/** Relative CIDR placed on a base block, e.g. ('0.0.13.0/24', '10.9.0.0') -> '10.9.13.0/24'. */
export function relocate(rel, base) {
  const R = parseCidr(rel);
  return cidr((ipToInt(base.split('/')[0]) + R.net) >>> 0, R.prefix);
}
