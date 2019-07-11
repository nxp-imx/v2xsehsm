/*
   (c) NXP B.V. 2017. All rights reserved.

   Disclaimer
   1. The NXP Software/Source Code is provided to Licensee "AS IS" without any
      warranties of any kind. NXP makes no warranties to Licensee and shall not
      indemnify Licensee or hold it harmless for any reason related to the NXP
      Software/Source Code or otherwise be liable to the NXP customer. The NXP
      customer acknowledges and agrees that the NXP Software/Source Code is
      provided AS-IS and accepts all risks of utilizing the NXP Software under
      the conditions set forth according to this disclaimer.

   2. NXP EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING,
      BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
      FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY
      RIGHTS. NXP SHALL HAVE NO LIABILITY TO THE NXP CUSTOMER, OR ITS
      SUBSIDIARIES, AFFILIATES, OR ANY OTHER THIRD PARTY FOR ANY DAMAGES,
      INCLUDING WITHOUT LIMITATION, DAMAGES RESULTING OR ALLEGDED TO HAVE
      RESULTED FROM ANY DEFECT, ERROR OR OMMISSION IN THE NXP SOFTWARE/SOURCE
      CODE, THIRD PARTY APPLICATION SOFTWARE AND/OR DOCUMENTATION, OR AS A
      RESULT OF ANY INFRINGEMENT OF ANY INTELLECTUAL PROPERTY RIGHT OF ANY
      THIRD PARTY. IN NO EVENT SHALL NXP BE LIABLE FOR ANY INCIDENTAL,
      INDIRECT, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES
      (INCLUDING LOST PROFITS) SUFFERED BY NXP CUSTOMER OR ITS SUBSIDIARIES,
      AFFILIATES, OR ANY OTHER THIRD PARTY ARISING OUT OF OR RELATED TO THE NXP
      SOFTWARE/SOURCE CODE EVEN IF NXP HAS BEEN ADVISED OF THE POSSIBILITY OF
      SUCH DAMAGES.

   3. NXP reserves the right to make changes to the NXP Software/Sourcecode any
      time, also without informing customer.

   4. Licensee agrees to indemnify and hold harmless NXP and its affiliated
      companies from and against any claims, suits, losses, damages,
      liabilities, costs and expenses (including reasonable attorney's fees)
      resulting from Licensee's and/or Licensee customer's/licensee's use of the
      NXP Software/Source Code.

 */

/*******************************************************************************
 *
 * \file v2xSeCommTypes.h
 *
 * \author SANDEEP BB
 *
 * \version 3.5
 *
 * \brief   This file contains common types
 *          This file must be included when using the library.
 *
 *
 *******************************************************************************/

#ifndef V2XSECOMMTYPES_H_
#define V2XSECOMMTYPES_H_

/******************************************************************************
 * INCLUDES
 *****************************************************************************/

/******************************************************************************
 * DEFINES
 *****************************************************************************/

#define V2XSE_SUCCESS 0
#define V2XSE_FAILURE -1
#define V2XSE_DEVICE_NOT_CONNECTED -2
#define V2XSE_FAILURE_CONNECTED -3
#define V2XSE_FAILURE_ACTIVATED -4
#define V2XSE_FAILURE_INIT  -5
#define V2XSE_FAILURE_RMAC  -6
#define V2XSE_FAILURE_KEY_FILE -7


#define V2XSE_SCP03_KEYFILE_ERROR (0x6F03u) //Error associated with key file - missing file, invalid key length or invalid number of keys
#define V2XSE_SCP03_SESSIONKEY_ERROR (0x6F04u) //Session key derivation failed
#define V2XSE_SCP03_CARDCRYPTO_ERROR (0x6F05u)  //Card cryptogram verification failed
#define V2XSE_SCP03_HOSTCRYPTO_ERROR (0x6F06u) //Host cryptogram verification failed
#define V2XSE_FAILURE_CHALLENGE_ERROR (0x6F08u)//Invalid or old host challenge

#endif

