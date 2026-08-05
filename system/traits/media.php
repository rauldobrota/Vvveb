<?php

/**
 * Vvveb
 *
 * Copyright (C) 2022  Ziadin Givan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

namespace Vvveb\System\Traits;

use function Vvveb\__;
use function Vvveb\fileUploadErrMessage;
use function Vvveb\parseQuantity;
use function Vvveb\rrmdir;
use function Vvveb\sanitizeFileName;
use Vvveb\System\Event;

/**
 * Trait providing file upload, deletion, renaming, folder creation, and directory scanning.
 *
 * Includes security checks for denied extensions, MIME types, executable signatures,
 * and path traversal prevention.
 */
trait Media {
	/**
	 * File extensions that are not allowed for upload.
	 *
	 * @var list<string>
	 */
	public array $uploadDenyExtensions = ['php', 'svg', 'js', 'exe', 'html', 'phtml', 'htaccess', 'phar'];

	/**
	 * MIME types that are not allowed for upload.
	 *
	 * @var list<string>
	 */
	public array $uploadDenyMime = ['image/svg', 'image/svg+xml', 'application/javascript', 'application/x-msdownload'];

	/**
	 * MIME types whose EXIF/metadata will be stripped on upload.
	 *
	 * @var list<string>
	 */
	public array $stripMetadataMime = ['image/jpg', 'image/jpeg', 'image/png', 'image/webp', 'image/avif'];

	/**
	 * Signatures checked at the start of a file to detect disguised executables.
	 *
	 * @var list<string>
	 */
	public array $denySignatures = ['<?php'];

	/**
	 * Return the filesystem path for a given directory type.
	 *
	 * @param string $type One of 'public', 'plugins', or 'themes'.
	 *
	 * @return string|false The directory path, or false if the type is invalid.
	 */
	protected function dirForType(string $type) : string|false {
		switch ($type) {
			case 'public':
				$scandir = DIR_MEDIA;

				break;

			case 'plugins':
				$scandir = DIR_PLUGINS;

				break;

			case 'themes':
				$scandir = DIR_THEMES;

				break;

			default:
				return false;
		}

		return $scandir;
	}

	/**
	 * Set the media-related URLs and upload limits on the view.
	 *
	 * @param string $controllerPath Base controller URL path.
	 * @param string $params         Additional URL query parameters.
	 *
	 * @return void
	 */
	protected function setMediaEndpoints(string $controllerPath, string $params = '') : void {
		$this->view->mediaUrl          = $controllerPath;
		$this->view->scanUrl           = "$controllerPath&action=scan$params";
		$this->view->uploadUrl         = "$controllerPath&action=upload$params";
		$this->view->deleteUrl         = "$controllerPath&action=delete$params";
		$this->view->renameUrl         = "$controllerPath&action=rename$params";
		$this->view->uploadMaxFilesize = parseQuantity(ini_get('upload_max_filesize'));
		$this->view->postMaxSize       = parseQuantity(ini_get('post_max_size'));
	}

	/**
	 * Check whether the first 16 bytes of a file contain a denied signature.
	 *
	 * @param string $file Absolute file path.
	 *
	 * @return bool True if the file contains a denied signature (e.g. PHP tag).
	 */
	protected function isExecutableFile(string $file) : bool {
		if (file_exists($file)) {
			/** @var string|false $header */
			$header = file_get_contents($file, false, null, 0, 16);
			if ($header) {
				foreach ($this->denySignatures as $signature) {
					if (strpos($header, $signature) !== false) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Handle file upload(s) from the media manager.
	 *
	 * Validates extensions, MIME types, file signatures, hidden files, and
	 * path traversal. Moves valid files to the destination directory and
	 * returns a JSON response.
	 *
	 * @return void
	 */
	public function upload() : void {
		/** @var array<int, array{name: list<string>, tmp_name: list<string>, error: list<int>, size: list<int>}> $files */
		$files      = $this->request->files['files'] ?? [];
		/** @var bool $overwrite */
		$overwrite  = $this->request->post['overwrite'] ?? false;
		$success    = false;
		$return     = '';
		$message    = '';
		/** @var list<array{success: bool, message: string, file: string, size?: int}> $response */
		$response   = [];

		/** @var list<array{name: list<string>, tmp_name: list<string>, error: list<int>, size: list<int>}> $files */
		list($files) = Event::trigger(__CLASS__, __FUNCTION__, $files, $this);

		if ($files) {
			$length = count($files['name'] ?? []);

			for ($count = 0; $count < $length; $count++) {
				$path      = sanitizeFileName((string) ($this->request->post['mediaPath'] ?? ''));
				$fileName  = sanitizeFileName($files['name'][$count]);

				if (! $fileName) {
					continue;
				}

				if (V_SUBDIR_INSTALL && strpos($path, V_SUBDIR_INSTALL) === 0) {
					$path  = substr_replace($path, '', 0, strlen(V_SUBDIR_INSTALL));
				}

				$path      = preg_replace('@.*[\\\/]public[\\\/]media|.*[\\\/]media|.*[\\\/]public@', '', $path);
				$extension = strtolower(substr($fileName, strrpos($fileName, '.') + 1));
				$mimeType  = mime_content_type($files['tmp_name'][$count]);

				if ($files['error'][$count] == UPLOAD_ERR_OK) {
					$success = true;
				} else {
					$message = fileUploadErrMessage($files['error'][$count]);
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				if (in_array($extension, $this->uploadDenyExtensions)) {
					$message .= sprintf(__('File type %s not allowed!'), $extension);
					$success = false;
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				if (in_array($mimeType, $this->uploadDenyMime)) {
					$message .= sprintf(__('File type %s not allowed!'), $mimeType);
					$success = false;
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				if (in_array($mimeType, $this->stripMetadataMime)) {
					//metadata stripping should be handled by the caller
					$files['tmp_name'][$count];
				}

				//deny hidden files
				if ($fileName[0] === '.') {
					$message .= __('Invalid upload!');
					$success = false;
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				//check if the path is inside the allowed path
				/** @var string|false $destination */
				$destination = realpath($this->dirMedia . DS . $path . DS);
				if (strncmp((string) $destination, $this->dirMedia, strlen($this->dirMedia) - 1) !== 0) {
					$message .= __('Invalid upload!');
					$success = false;
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				//check if it's not a php file disguised as an image
				if ($this->isExecutableFile($files['tmp_name'][$count])) {
					$message .= sprintf(__('File type %s not allowed!'), 'PHP');
					$success = false;
					$response[] = ['success' => $success, 'message' => $message, 'file' => $fileName];
					continue;
				}

				$origFilename = $fileName;
				$i            = 1;

				if ($success) {
					$destination .= DS . $fileName;
					$message .= $destination;
					if (! $overwrite) {
						while (file_exists($destination = $this->dirMedia . $path . DS . $fileName) && ($i++ < 5)) {
							$fileName = rand(0, 10000) . '-' . $origFilename;
						}
					}

					if (@move_uploaded_file($files['tmp_name'][$count], $destination)) {
						if (isset($this->request->post['onlyFilename'])) {
							$return = $fileName;
						} else {
							$return = $path . DS . $fileName;
						}
						$message = __('File uploaded successfully!');
					} else {
						$destination = $this->dirMedia . $path . DS;
						$success     = false;

						if (! is_writable((string) $destination)) {
							$message = sprintf(__('%s not writable!'), $destination);
						} else {
							$message = __('Error moving uploaded file!');
						}
					}
				}

				$response[] = ['success' => $success, 'message' => $message, 'file' => $return, 'size' => $files['size'][$count]];
			}
		} else {
			$message    = __('Invalid upload!');
			$response[] = ['success' => $success, 'message' => $message, 'file' => $return];
		}

		$this->response->setType('json');
		$this->response->output($response);
	}

	/**
	 * Delete a file or directory from the media folder.
	 *
	 * Supports deleting a single file/directory or an array of files.
	 * Returns a JSON response.
	 *
	 * @return void
	 */
	public function delete() : void {
		/** @var string|array<int, string> $file */
		$file        = $this->request->post['file'];
		/** @var array{success: bool, message: string} $message */
		$message     = ['success' => false, 'message' => __('Error deleting file!')];
		$themeFolder = $this->dirMedia;

		if ($file) {
			if (is_array($file)) {
				foreach ($file as $f) {
					$f = sanitizeFileName($f);
					$path = $themeFolder . DS . $f;

					if (@unlink($path)) {
						$message = ['success' => true, 'message' => __('File deleted!')];
					} else {
						$message = ['success' => false, 'message' => sprintf(__('Error deleting %s!'), $f)];
						break;
					}
				}
			} else {
				$file        = sanitizeFileName($this->request->post['file']);
				$path        = $themeFolder . DS . $file;

				if (is_dir($path)) {
					if (@rrmdir($path)) {
						$message = ['success' => true, 'message' => __('File deleted!')];
					}
				} else {
					if (@unlink($path)) {
						$message = ['success' => true, 'message' => __('File deleted!')];
					}
				}
			}
		}

		$this->response->setType('json');
		$this->response->output($message);
	}

	/**
	 * Rename or copy a file in the media folder.
	 *
	 * When $duplicate is true, the file is copied instead of renamed.
	 * Returns a JSON response.
	 *
	 * @return void
	 */
	public function rename() : void {
		$file        = sanitizeFileName($this->request->post['file']);
		$newfile     = sanitizeFileName((string) ($this->request->post['newfile'] ?? ''));
		$newname     = sanitizeFileName((string) ($this->request->post['newname'] ?? ''));
		/** @var bool $duplicate */
		$duplicate   = $this->request->post['duplicate'] ?? false;
		$dirMedia    = $this->dirMedia;

		$this->response->setType('json');

		$currentFile = $dirMedia . DS . $file;
		/** @var string $targetFile */
		$targetFile  = $currentFile;

		if ($newfile) {
			$targetFile = $dirMedia . DS . $newfile;
		}

		if ($newname) {
			$targetFile = dirname($currentFile) . DS . $newname;
		}

		$extension = strtolower(substr($targetFile, strrpos($targetFile, '.') + 1));

		if (in_array($extension, $this->uploadDenyExtensions)) {
			$message = ['success' => false, 'message' => __('File type not allowed!')];
			$this->response->output($message);
			return;
		}

		if ($duplicate) {
			if (copy($currentFile, $targetFile)) {
				$message = ['success' => true, 'message' => __('File copied!')];
			} else {
				$message = ['success' => false, 'message' => __('Error copying file!')];
			}
		} else {
			if (rename($currentFile, $targetFile)) {
				$message = ['success' => true, 'message' => __('File renamed!')];
			} else {
				$message = ['success' => false, 'message' => __('Error renaming file!')];
			}
		}

		$this->response->output($message);
	}

	/**
	 * Create a new folder inside the media directory.
	 *
	 * Returns a JSON response with success or error message.
	 *
	 * @return void
	 */
	public function newFolder() : void {
		$folder  = sanitizeFileName($this->request->post['folder']);
		$path    = sanitizeFileName($this->request->post['path']);
		$success = false;

		$dirMedia = $this->dirMedia;

		if (is_dir($dirMedia . $path)) {
			if (is_dir($dirMedia . $path . DS . $folder)) {
				$message = __('Folder already exists!');
			} else {
				if (@mkdir($dirMedia . $path . DS . $folder)) {
					$message = __('Folder created!');
					$success = true;
				} else {
					$message = __('Error creating folder!');
				}
			}
		} else {
			$message = __('Path does not exist!');
		}

		$message = ['success' => $success, 'message' => $message];

		$this->response->setType('json');
		$this->response->output($message);
	}

	/**
	 * Recursively scan the media directory and return a JSON tree of files and folders.
	 *
	 * @return void
	 */
	public function scan() : void {
		$scandir = $this->dirMedia;

		if (isset($this->dirMediaType) && $this->dirMediaType) {
			/** @var string $type */
			$type    = $this->request->get['type'] ?? 'public';
			$scandir = $this->dirForType($type);
		}

		if (! $scandir) {
			$this->response->setType('json');
			$this->response->output([]);
			return;
		}

		// This function scans the files folder recursively, and builds a large array
		/** @var \Closure(string): list<array{name: string, type: string, path: string, items?: mixed[], size?: int}> $scan */
		$scan = function (string $dir) use ($scandir, &$scan) : array {
			$files = [];

			// Is there actually such a folder/file?

			if (file_exists($dir)) {
				/** @var list<string>|false $listdir */
				$listdir = @\scandir($dir);

				if ($listdir) {
					foreach ($listdir as $f) {
						if (! $f || $f[0] === '.' || $f === 'node_modules' || $f === 'vendor') {
							continue;// Ignore hidden files
						}

						if (is_dir($dir . DS . $f)) {
							// The path is a folder

							$files[] = [
								'name'  => $f,
								'type'  => 'folder',
								'path'  => str_replace([$scandir, '\\'], ['', '/'], $dir) . '/' . $f,
								'items' => $scan("$dir/$f"),
							];
						} else {
							// It is a file

							$files[] = [
								'name' => $f,
								'type' => 'file',
								'path' => str_replace([$scandir, '\\'], ['', '/'], $dir) . '/' . $f,
								'size' => filesize("$dir/$f"),
							];
						}
					}
				}
			}

			return $files;
		};

		$response = $scan($scandir);

		$this->response->setType('json');
		$this->response->output([
			'name'  => '',
			'type'  => 'folder',
			'path'  => '',
			'items' => $response,
		]);
	}
}
