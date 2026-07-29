package hue.captains.singapura.tao.http.config.builtin;

import hue.captains.singapura.tao.http.config.ByteSourceSpec;

/**
 * Built-in {@link ByteSourceSpec}: bytes read from a file on the local filesystem.
 * Fulfilled by {@link FileByteSourceResolver}.
 *
 * @param path filesystem path of the file to read
 */
public record FileByteSource(String path) implements ByteSourceSpec {
}
