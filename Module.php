<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailLoginFormWebclient;

/**
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2019, Afterlogic Corp.
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractWebclientModule
{
	/***** public functions might be called with web API *****/
	/**
	 * Obtains list of module settings for authenticated user.
	 * 
	 * @return array
	 */
	public function GetSettings()
	{
		\Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);
		
		return array(
			'ServerModuleName' => $this->getConfig('ServerModuleName', ''),
			'HashModuleName' => $this->getConfig('HashModuleName', ''),
			'CustomLoginUrl' => $this->getConfig('CustomLoginUrl', ''),
			'FormType' => $this->getConfig('FormType', null),
			'DemoLogin' => $this->getConfig('DemoLogin', ''),
			'DemoPassword' => $this->getConfig('DemoPassword', ''),
			'InfoText' => $this->getConfig('InfoText', ''),
			'BottomInfoHtmlText' => $this->getConfig('BottomInfoHtmlText', ''),
			'LoginSignMeType' => $this->getConfig('LoginSignMeType', 0),
			'AllowChangeLanguage' => $this->getConfig('AllowChangeLanguage', true),
			'UseDropdownLanguagesView' => $this->getConfig('UseDropdownLanguagesView', false),
		);
	}
	
	public function Login($Email, $Login, $Password, $Language = '', $SignMe = false)
	{
		\Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);
		$mResult = false;

		$bResult = false;
		$oServer = null;
		$iUserId = 0;
		$sEmail = \trim($Email);
		$sLogin = empty(\trim($Login)) ? $sEmail : \trim($Login);
		$sPassword = $Password;
		if (empty($sEmail))
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
		}
		$oAccount = \Aurora\System\Api::getModule('Mail')->getAccountsManager()->getAccountUsedToAuthorize($sEmail);

		$bNewAccount = false;
		$bAutocreateMailAccountOnNewUserFirstLogin = \Aurora\Modules\Mail\Module::Decorator()->getConfig('AutocreateMailAccountOnNewUserFirstLogin', false);

		if ($bAutocreateMailAccountOnNewUserFirstLogin && !$oAccount)
		{
			$sDomain = \MailSo\Base\Utils::GetDomainFromEmail($sEmail);
			$oServer = \Aurora\System\Api::getModule('Mail')->getServersManager()->GetServerByDomain(strtolower($sDomain));
			if (!$oServer)
			{
				$oServer = \Aurora\System\Api::getModule('Mail')->getServersManager()->GetServerByDomain('*');
			}
			if ($oServer)
			{
				$oAccount = new \Aurora\Modules\Mail\Classes\Account(self::GetName());
				$oAccount->Email = $sEmail;
				$oAccount->IncomingLogin = $sLogin;
				$oAccount->setPassword($sPassword);
				$oAccount->ServerId = $oServer->EntityId;
				$bNewAccount = true;
			}
		}

		if ($oAccount instanceof \Aurora\Modules\Mail\Classes\Account)
		{
			try
			{
				if ($bAutocreateMailAccountOnNewUserFirstLogin || !$bNewAccount)
				{
					$bNeedToUpdatePasswordOrLogin = $sPassword !== $oAccount->getPassword() || $sLogin !== $oAccount->IncomingLogin;
					$oAccount->IncomingLogin = $sLogin;
					$oAccount->setPassword($sPassword);

					\Aurora\System\Api::getModule('Mail')->getMailManager()->validateAccountConnection($oAccount);

					if ($bNeedToUpdatePasswordOrLogin)
					{
						\Aurora\System\Api::getModule('Mail')->getAccountsManager()->updateAccount($oAccount);
					}

					$bResult =  true;
				}

				if ($bAutocreateMailAccountOnNewUserFirstLogin && $bNewAccount)
				{
					$oUser = null;
					$aSubArgs = array(
						'UserName' => $sEmail,
						'Email' => $sEmail,
						'UserId' => $iUserId
					);
					$this->broadcastEvent(
						'CreateAccount',
						$aSubArgs,
						$oUser
					);
					if ($oUser instanceof \Aurora\Modules\Core\Classes\User)
					{
						$iUserId = $oUser->EntityId;
						$bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
						$oAccount = \Aurora\Modules\Mail\Module::Decorator()->CreateAccount(
							$iUserId,
							$sEmail,
							$sEmail,
							$sLogin,
							$sPassword,
							array('ServerId' => $oServer->EntityId)
						);
						\Aurora\System\Api::skipCheckUserRole($bPrevState);
						if ($oAccount)
						{
							$oAccount->UseToAuthorize = true;
							$oAccount->UseThreading = $oServer->EnableThreading;
							$bResult = \Aurora\System\Api::getModule('Mail')->getAccountsManager()->updateAccount($oAccount);
						}
						else
						{
							$bResult = false;
						}
					}
				}

				if ($bResult)
				{
					$mResult = array(
						'token' => 'auth',
						'id' => $oAccount->IdUser,
						'account' => $oAccount->EntityId,
						'account_type' => $oAccount->getName()
					);
				}
			}
			catch (\Aurora\System\Exceptions\ApiException $oException)
			{
				throw $oException;
			}
			catch (\Exception $oException) {}
		}

		if (is_array($mResult))
		{
			$iTime = $SignMe ? 0 : time();
			$sAuthToken = \Aurora\System\Api::UserSession()->Set($mResult, $iTime);

			//this will store user data in static variable of Api class for later usage
			$oUser = \Aurora\System\Api::getAuthenticatedUser($sAuthToken);

			if ($oUser->Role !== \Aurora\System\Enums\UserRole::SuperAdmin)
			{
				// If User is super admin don't try to detect tenant. It will try to connect to DB.
				// Super admin should be able to log in without connecting to DB.
				$oTenant = \Aurora\System\Api::getTenantByWebDomain();
				if ($oTenant && $oUser->IdTenant !== $oTenant->EntityId)
				{
					throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AuthError);
				}
			}

			if ($Language !== '' && $oUser && $oUser->Language !== $Language)
			{
				$oUser->Language = $Language;
				$this->getUsersManager()->updateUser($oUser);
			}

			\Aurora\System\Api::LogEvent('login-success: ' . $sLogin, self::GetName());
			$mResult = [
				'AuthToken' => $sAuthToken
			];
		}
		else
		{
			\Aurora\System\Api::LogEvent('login-failed: ' . $sLogin, self::GetName());
			\Aurora\System\Api::GetModuleManager()->SetLastException(
				new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AuthError)
			);
		}

		return $mResult;
	}
	
	public function GetMailDomains()
	{
		\Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);
		
		$bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
		$aServers = \Aurora\Modules\Mail\Module::Decorator()->GetServers(2);
		\Aurora\System\Api::skipCheckUserRole($bPrevState);
		
		$aAllDomains = [];
		if ($aServers)
		{
			foreach ($aServers as $oServer)
			{
				$aDomains = explode("\n", $oServer->Domains);
				$aDomains = array_filter($aDomains, function($sDomain) {
					return $sDomain !== '*';
				});
				$aAllDomains = array_merge($aAllDomains, $aDomains);
			}
		}
		return $aAllDomains;
	}
	/***** public functions might be called with web API *****/
}
