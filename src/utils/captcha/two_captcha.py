import base64
import os
import time
import traceback
from types import LambdaType
from typing import Dict

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from twocaptcha import TwoCaptcha
from twocaptcha.api import ApiException, NetworkException
from twocaptcha.solver import TimeoutException

from src.utils.common import selenium_common, utils
from src.utils.log import Log

import json
import re

DEFAULT_CONFIG = {"api_key": None, "enabled": True, "debug_mode": True}


class Captcha:
    def __init__(self, log: Log, config: Dict = DEFAULT_CONFIG):
        solver = TwoCaptcha(apiKey=config["api_key"])
        self.solver = solver
        self.log = log
        self.enabled = config["enabled"]
        self.debug_enabled = config["debug_mode"]

    def _solve_captcha(
        self,
        solve_callback: LambdaType,
        result_callback: LambdaType,
        debug_enabled: bool,
    ):
        result = None
        try:
            result = solve_callback()
            self.log.debug_if(debug_enabled, "Received 2Captcha response...")
        except TimeoutException as e:
            self.log.debug_if(debug_enabled, f"2Captcha API has timed-out! : {str(e)}")
            result = (False, "TIMEOUT", e)
        except NetworkException as e:
            self.log.debug_if(
                debug_enabled,
                f"2Captcha API has encountered a network error! : {str(e)}",
            )
            result = (False, "NETWORK_ERROR", e)
        except ApiException as e:
            self.log.debug_if(
                debug_enabled, f"2Captcha API has encountered an API error : {str(e)}"
            )
            result = (False, "API_ERROR", e)
        except Exception as e:
            self.log.error(e)
            self.log.error(traceback.format_exc())
            result = (False, "UNKNOWN_ERROR", e)
        else:
            result_callback(result)
            result = (True, "SOLVED", result)
        finally:
            self.log.debug_if(debug_enabled, result)
            return result

    def save_captcha(self, driver: webdriver, captcha_image_filepath: str):
        captcha_element = selenium_common.is_elem_present(
            driver, By.ID, "ctl00_ContentPlaceHolder1_CaptchaImg"
        )
        captcha_input = selenium_common.is_elem_present(
            driver, By.ID, "ctl00_ContentPlaceHolder1_txtVerificationCode"
        )

        if captcha_element and captcha_input:
            img_base64_str = captcha_element.get_attribute("src")[23:]
            img_base64 = str.encode(img_base64_str)

            with open(captcha_image_filepath, "wb") as image_file:
                image_file.write(base64.decodebytes(img_base64))

            return captcha_input

        return False

    def normal_captcha(self, driver: webdriver, page_url: str, debug_enabled: bool):
        captcha_image_filepath = os.path.join("temp", "normal_captcha.jpeg")
        captcha_input = self.save_captcha(driver, captcha_image_filepath)
        if captcha_input:
            success, status, msg = self._solve_captcha(
                solve_callback=lambda: self.solver.normal(
                    captcha_image_filepath, caseSensitive=1, minLength=6, maxLength=6
                ),
                result_callback=lambda result: captcha_input.send_keys(
                    str(result["code"])
                ),
                debug_enabled=debug_enabled,
            )

            if (
                self.log.config["save_solved_captchas"]
                and success
                and status == "SOLVED"
            ):
                os.rename(
                    captcha_image_filepath,
                    os.path.join("solved_captchas", f"{msg['code']}.jpeg"),
                )
            else:
                utils.remove_files([captcha_image_filepath])

            return success, status, msg

        return False, "NO CAPTCHA FOUND IN", page_url

    def recaptcha_v2(self, driver: webdriver, page_url: str, debug_enabled: bool):
        def submit_captcha_response(driver, result):
            recaptcha_repsonse_element = driver.find_element(
                By.ID, "g-recaptcha-response"
            )
            driver.execute_script(
                f'arguments[0].value="{result["code"]}"', recaptcha_repsonse_element
            )

        site_key_element = selenium_common.is_elem_present(
            driver, By.CSS_SELECTOR, "[data-sitekey]"
        )
        if site_key_element:
            site_key = site_key_element.get_attribute("data-sitekey")
            return self._solve_captcha(
                solve_callback=lambda: self.solver.recaptcha(
                    sitekey=site_key, url=page_url
                ),
                # result_callback=lambda result: driver.execute_script(
                #     """document.querySelector('[id="g-recaptcha-response"]').innerText = '{}'""".format(
                #         str(result["code"])
                #     )
                # ),
                result_callback=lambda result: submit_captcha_response(driver, result),
                debug_enabled=debug_enabled,
            )

        return False, "NO RECAPTCHA_V2 FOUND IN", page_url

    def get_captcha_params(self, driver: webdriver):
        """
        Refreshes the page, injects a JavaScript script to intercept Turnstile parameters, and retrieves them.

        Args:
            script (str): The JavaScript code to be injected.

        Returns:
            dict: The intercepted Turnstile parameters as a dictionary.
        """
        intercept_script = """ 
            console.clear = () => console.log('Console was cleared')
            const i = setInterval(()=>{
            if (window.turnstile)
            console.log('success!!')
            {clearInterval(i)
                window.turnstile.render = (a,b) => {
                let params = {
                        sitekey: b.sitekey,
                        pageurl: window.location.href,
                        data: b.cData,
                        pagedata: b.chlPageData,
                        action: b.action,
                        userAgent: navigator.userAgent,
                    }
                    console.log('intercepted-params:' + JSON.stringify(params))
                    window.cfCallback = b.callback
                    return        } 
            }
        },50)    
        """

        driver.refresh()  # Refresh the page to ensure the script is applied correctly

        driver.execute_script(intercept_script)  # Inject the interception script

        time.sleep(5)  # Allow some time for the script to execute

        logs = driver.get_log("browser")  # Retrieve the browser logs
        params = None
        for log in logs:
            if "intercepted-params:" in log["message"]:
                log_entry = log["message"].encode("utf-8").decode("unicode_escape")
                match = re.search(r"intercepted-params:({.*?})", log_entry)
                if match:
                    json_string = match.group(1)
                    params = json.loads(json_string)
                    break
        print("Parameters received")
        return params

    def cf_solver_captcha(self, params, debug_enabled: bool):
        """
        Solves the Turnstile captcha using the 2Captcha service.

        Args:
            params (dict): The intercepted Turnstile parameters.

        Returns:
            str: The solved captcha token.
        """

        try:
            result = self.solver.turnstile(
                sitekey=params["sitekey"],
                url=params["pageurl"],
                action=params["action"],
                data=params["data"],
                pagedata=params["pagedata"],
                useragent=params["userAgent"],
            )
            self.log.debug_if(debug_enabled, f"Captcha solved")
            return result["code"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def send_token_callback(self, driver: webdriver, token):
        """
        Executes the callback function with the given token.

        Args:
            token (str): The solved captcha token.
        """
        script = f"cfCallback('{token}')"
        driver.execute_script(script)
        print("The token is sent to the callback function")

    def cf_final_message(self, driver: webdriver, locator):
        """
        Retrieves and prints the final success message.

        Args:
            locator (str): The XPath locator of the success message.
        """
        message = (
            WebDriverWait(driver, 30)
            .until(EC.element_to_be_clickable((By.XPATH, locator)))
            .text
        )
        print(message)

    def cloudflare_turnstile(self, driver: webdriver, debug_enabled: bool):
        params = self.get_capture_params(driver)

        if params:
            token = self.cf_solver_captcha(params, debug_enabled)

            if token:
                self.send_token_callback(token)
                self.cf_final_message(driver, "//p[contains(@class,'successMessage')]")
                time.sleep(5)
            else:
                print("Failed to solve Cloudflare turnstile")
        else:
            print("Cloudflare turnstile: failed to intercept parameters")

    def solve(
        self,
        driver: webdriver,
        captcha_type: str = None,
        page_url: str = None,
        force_enable: bool = False,
        force_debug: bool = False,
    ):
        t_start = time.perf_counter()
        page_url = page_url or driver.current_url
        captcha_type = captcha_type or "recaptcha_v2"
        debug_enabled = self.debug_enabled or force_debug

        if self.enabled or force_enable:
            self.log.debug_if(
                debug_enabled, f"Solving {captcha_type.upper()} for: {page_url}"
            )

            success, status, msg = False, "", ""

            if captcha_type.lower() == "recaptcha_v2":
                success, status, msg = self.recaptcha_v2(
                    driver=driver, page_url=page_url, debug_enabled=debug_enabled
                )
            elif captcha_type.lower() == "normal_captcha":
                success, status, msg = self.normal_captcha(
                    driver=driver, page_url=page_url, debug_enabled=debug_enabled
                )

            status_msg = f"{status}: {msg}"
            if success:
                self.log.debug_if(
                    debug_enabled,
                    "Took {t} seconds to solve the {n} using two-captcha!".format(
                        t=time.perf_counter() - t_start, n=captcha_type.upper()
                    ),
                )

            return success, status_msg

        self.log.debug_if(debug_enabled, f"Manually solving CAPTCHA for: {page_url}")
        input("Press enter to proceed: ")

        if (
            self.log.config["save_solved_captchas"]
            and captcha_type.lower() == "normal_captcha"
        ):
            captcha_input = selenium_common.is_elem_present(
                driver, By.ID, "ctl00_ContentPlaceHolder1_txtVerificationCode"
            )
            if captcha_input:
                self.save_captcha(
                    driver,
                    os.path.join(
                        "solved_captchas",
                        f"{captcha_input.get_attribute('value')}.jpeg",
                    ),
                )

        self.log.debug_if(
            debug_enabled,
            "Took exactly {t} seconds to solve the {n} manually!".format(
                t=time.perf_counter() - t_start, n=captcha_type.upper()
            ),
        )
        return True, "Manually solved CAPTCHA"
