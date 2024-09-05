<?php
/**
 * WordPress Coding Standard.
 *
 * @package WPCS\WordPressCodingStandards
 * @link    https://github.com/WordPress/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

namespace WordPressCS\WordPress\Sniffs\Security;

use WordPressCS\WordPress\Sniff;

/**
 * Avoid direct link for php files.
 *
 * @since 3.2.0
 */
final class DirectFileAccessSniff {

	/**
	 * Direct file access variables that should be in a file.
	 *
	 * @link 
	 *
	 * @since 3.2.0
	 *
	 * @var array<string, true>
	 */
	private $cdirect_fileaccess_vars_superglobals = array(
		'ABPATH' => true,
		'WPINC'  => true,
	);

	

}
