<?php
/**
 * WordPress Coding Standard.
 *
 * @package WPCS\WordPressCodingStandards
 * @link    https://github.com/WordPress/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

namespace WordPressCS\WordPress\Sniffs\Security;

use PHP_CodeSniffer\Util\Tokens;
use PHPCSUtils\Tokens\Collections;
use WordPressCS\WordPress\Sniff;

/**
 * Avoid direct link for php files.
 *
 * @since 3.2.0
 */
final class DirectFileAccessSniff extends Sniff {

	/**
	 * Direct file access variables that should be in a file.
	 *
	 * @link 
	 *
	 * @since 3.2.0
	 *
	 * @var array<string, true>
	 */
	private static $direct_fileaccess_vars_superglobals = array(
		'ABPATH' => true,
		'WPINC'  => true,
	);

	/**
	 * The tokens that indicate the start of a condition.
	 *
	 * @since n.e.x.t.
	 *
	 * @var array
	 */
	private $condition_start_tokens;

	/**
	 * Returns an array of tokens this test wants to listen for.
	 *
	 * @return array
	 */
	public function register() {

		$starters                        = Tokens::$booleanOperators;
		$starters                       += Tokens::$assignmentTokens;
		$starters[ \T_OPEN_TAG ]         = \T_OPEN_TAG;
		$starters[ \T_STRING ]           = \T_STRING;

		$this->condition_start_tokens = $starters;

		return array(
			\T_STRING,
			\T_CONSTANT_ENCAPSED_STRING,
		);
	}

	/**
	 * Processes this test, when one of its tokens is encountered.
	 *
	 * @param int $stackPtr The position of the current token in the stack.
	 *
	 * @return void
	 */
	public function process_token( $stackPtr ) {

		$start = $this->phpcsFile->findPrevious( $this->condition_start_tokens, $stackPtr, null, false, null, true );

		$keys_string = implode(' ', array_keys( self::$direct_fileaccess_vars_superglobals ) );

		$needs_yoda = false;

		// Note: going backwards!
		for ( $i = $stackPtr; $i > $start; $i-- ) {

			// Ignore whitespace.
			if ( isset( Tokens::$emptyTokens[ $this->tokens[ $i ]['code'] ] ) ) {
				continue;
			}
			var_dump( $this->tokens[ $i ] );
			if ( \T_CONSTANT_ENCAPSED_STRING === $this->tokens[ $i ]['type']
				&& preg_match('/' . preg_quote( $this->tokens[ $i ]['content'], '/') . '/', $keys_string ) ) {
				var_dump( $this->tokens[ $i ] );
				die();
				return;
			}

			// If this is a variable or array assignment, we've seen all we need to see.
			if ( \T_VARIABLE === $this->tokens[ $i ]['code']
				|| \T_CLOSE_SQUARE_BRACKET === $this->tokens[ $i ]['code']
			) {
				$needs_yoda = true;
				break;
			}

			// If this is a function call or something, we are OK.
			if ( \T_CLOSE_PARENTHESIS === $this->tokens[ $i ]['code'] ) {
				return;
			}
		}

		if ( ! $needs_yoda ) {
			return;
		}

		// Check if this is a var to var comparison, e.g.: if ( $var1 == $var2 ).
		$next_non_empty = $this->phpcsFile->findNext( Tokens::$emptyTokens, ( $stackPtr + 1 ), null, true );

		if ( isset( Tokens::$castTokens[ $this->tokens[ $next_non_empty ]['code'] ] ) ) {
			$next_non_empty = $this->phpcsFile->findNext( Tokens::$emptyTokens, ( $next_non_empty + 1 ), null, true );
		}

		if ( isset( Collections::ooHierarchyKeywords()[ $this->tokens[ $next_non_empty ]['code'] ] ) === true ) {
			$next_non_empty = $this->phpcsFile->findNext(
				( Tokens::$emptyTokens + array( \T_DOUBLE_COLON => \T_DOUBLE_COLON ) ),
				( $next_non_empty + 1 ),
				null,
				true
			);
		}

		if ( \T_VARIABLE === $this->tokens[ $next_non_empty ]['code'] ) {
			return;
		}

		$this->phpcsFile->addError( 'Use Yoda Condition checks, you must.', $stackPtr, 'NotYoda' );
	}
}
