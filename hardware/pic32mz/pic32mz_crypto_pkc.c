/**
 * @file pic32mz_crypto_pkc.c
 * @brief PIC32MZ W1 public-key hardware accelerator (BA414E)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <p32xxxx.h>
#include <sys/kmem.h>
#include "core/crypto.h"
#include "hardware/pic32mz/pic32mz_crypto.h"
#include "hardware/pic32mz/pic32mz_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ec_misc.h"
#include "ecc/ecdsa.h"
#include "ecc/x25519.h"
#include "ecc/ed25519.h"
#include "debug.h"

//Check crypto library configuration
#if (PIC32MZ_CRYPTO_PKC_SUPPORT == ENABLED) && defined(_PMD1_BA414MD_MASK)

//BA414E microcode
static const uint32_t ucode[] =
{
   0x10032004, 0x48013E00, 0x5A800D20, 0x09A80202, 0x011A8090, 0x60287805, 0xBA022780, 0xB2E02FA8,
   0x0CEE0070, 0x8021E00A, 0xD8039A00, 0xF5802D60, 0x13C8023A, 0x013D8050, 0x60141804, 0xF2013E80,
   0x50201408, 0x14460540, 0x8070E01D, 0x48078205, 0x8C804FE0, 0x13F804FE, 0x013F8050, 0x2059B804,
   0xF6035A80, 0xF3204118, 0x11B603AF, 0x8167E059, 0xF8167E05, 0x9E712014, 0x00144011, 0x10854441,
   0x80001702, 0x41C51100, 0x10000017, 0x0A490012, 0x4024A005, 0x17200000, 0x010000A0, 0x03678918,
   0x40007893, 0x44001730, 0x01F30209, 0xB1800015, 0x00040002, 0x800D9E24, 0x610001E2, 0x4D10005C,
   0xC007CE08, 0x26C60000, 0x54001000, 0x0A003640, 0xE45C580A, 0x80E9C29A, 0x7AB18C38, 0x07AD1CC3,
   0x8173001C, 0x8007AB2C, 0x23C67AD3, 0x023C67EA, 0x080D4B7A, 0xC6C0D4B0, 0x00054001, 0x0000A003,
   0x640E45C5, 0x80A80E9E, 0x11330E01, 0xE11430E0, 0x5E115026, 0x51C2927C, 0x4080A920, 0x00054001,
   0x00009C29, 0xA4086A00, 0x3640E460, 0x05D50004, 0x000270A4, 0x90212800, 0xD9039180, 0x1CD40010,
   0x000A0036, 0x40001E24, 0x610005E2, 0x4D10001C, 0xC007D808, 0x26C60000, 0x54001000, 0x09C58078,
   0x93440057, 0x89184004, 0x73001F40, 0x609B1800, 0x01802994, 0x0014044A, 0x003E4401, 0x90092444,
   0x1A004600, 0x00400027, 0x0A490212, 0x8026DCC0, 0x0A02D140, 0x015057C0, 0x00270A49, 0x02123401,
   0x5C580789, 0x34000078, 0x91840047, 0x3001F406, 0x09B19CC0, 0x0A02D100, 0x158040CD, 0x00044015,
   0x00804045, 0xA0046730, 0x0240B430, 0x05910054, 0x42191106, 0x80145000, 0x04421911, 0x0640E469,
   0x073E4175, 0x10044421, 0x91106801, 0x19120680, 0x26DC8003, 0x000200A6, 0x7300250E, 0x40000540,
   0x0174A180, 0x00100009, 0x00158040, 0xCC01570A, 0x49C80030, 0x249FA863, 0x0A11EB1B, 0x30A11C80,
   0x030000C0, 0x90500040, 0x00240056, 0x01033005, 0x5C292720, 0x00C0927C, 0x418C2847, 0x2000C000,
   0x30240000, 0x150005D2, 0x8072001E, 0x24610001, 0xE24D1000, 0x1CC0078E, 0x4C26C672, 0x000C0137,
   0x89180013, 0x73001F38, 0x009B19C8, 0x0000004C, 0x00030241, 0x01005025, 0xD4001000, 0x09C580A8,
   0x0E903917, 0x0A490016, 0x7C400839, 0x244021F1, 0x0030E111, 0x08020439, 0xF1093000, 0x51089284,
   0x01E88020, 0xE4AB59C7, 0x46148001, 0x20441C90, 0x072401C9, 0x0072401C, 0x98028400, 0xA0007E81,
   0x80900000, 0x05400150, 0x00540015, 0x00054001, 0x50005400, 0x17EA0048, 0x8172001F, 0xB0812224,
   0x00018050, 0x9EDC6022, 0x69FB1002, 0x269C8000, 0x0005C580, 0xA80E9C29, 0xA4021221, 0x5B442263,
   0x15B00041, 0x00844004, 0xA0142000, 0x05EAC612, 0x205EB470, 0x2201C800, 0x78F2C234, 0x77AB180D,
   0x4B7EC040, 0xD4B00004, 0x00027300, 0x1C800D45, 0xB4000150, 0x00540430, 0x000A014F, 0xAD675108,
   0x44010E01, 0x48442110, 0x01480509, 0x00434030, 0xF624798B, 0x450096D8, 0x85262BF4, 0x005A0142,
   0x4010D00C, 0x34045362, 0x9298C150, 0x098D8852, 0x62BF4006, 0x20142004, 0x02B59D74, 0x615C8002,
   0x00048120, 0x8467711A, 0xD72E01C8, 0x0028400A, 0x0004010D, 0x1086D885, 0x262BF000, 0x0601BD50,
   0x00500434, 0x030F6247, 0x98B47624, 0x798B4771, 0xA99C6AD0, 0x900D8A4A, 0x63050000, 0x50043000,
   0x05004C00, 0x00771AF0, 0x00050043, 0x42201F20, 0x010005F2, 0x0810025E, 0xDC602269, 0xFB100226,
   0xAC59D000, 0x80000150, 0x11DC8000, 0x002200A6, 0x44C3A00A, 0x60000400, 0x02020011, 0x00440201,
   0x011B8014, 0x5CC00720, 0x0341D344, 0x02200517, 0x3001C800, 0xD074C000, 0x15000540, 0x0B000080,
   0x80040005, 0x00804046, 0xE0051730, 0x01C80094, 0x77C00015, 0x0005400F, 0x00008080, 0x04001100,
   0x804046E0, 0x05173001, 0xC800D084, 0x91008801, 0x45CC0072, 0x00342129, 0x883E014F, 0x40449E24,
   0x610009E2, 0x4710029E, 0x34B08D19, 0xE34C08F1, 0xDEDCD097, 0x2DEB4B09, 0x72DE34C0, 0x8F31EACB,
   0x08D2DEB4, 0xC09931C3, 0x4E78D342, 0x64C78D2C, 0x264B70D3, 0x9E34C09B, 0x2DCC0072, 0x00252128,
   0x083C0002, 0x00005400, 0x14001140, 0x1B7B72CC, 0x8107AD18, 0xC8107300, 0x1C800946, 0xF1EDCB32,
   0x041EB472, 0x2119CC00, 0x7200251B, 0xC7D00463, 0x007D0246, 0x38800004, 0x00028053, 0xD1084401,
   0x0E014240, 0x44900437, 0x8930400A, 0x7AB2CC00, 0x07AD18C1, 0x007AB2C8, 0x04B7AD1C, 0xC40878D2,
   0xC234B70D, 0x35E34B09, 0x731C34D7, 0x8F1825C7, 0x8059C000, 0x28053D10, 0x844010E0, 0x1484030D,
   0xC80078D3, 0x4C48978D, 0x18C0817A, 0xB3484CD7, 0xAD38C891, 0x7AB1826C, 0x67AD1C26, 0xCD7AB2CC,
   0x0817AD34, 0x274E78D1, 0xC23C778D, 0x3025CB7B, 0x738094D7, 0xAD34094D, 0x78D30264, 0xB78D3823,
   0x4678D2C2, 0x6CC78D34, 0xC489A49F, 0x392827CE, 0x00274C72, 0x001E3CE2, 0x0119C800, 0x7EA4088C,
   0xD7AD3027, 0x4B72001F, 0x38808F30, 0x00014421, 0xA0214806, 0xF540017F, 0x62025CB7, 0xAD3025CB,
   0x72000000, 0x17AB3025, 0xCB7EC202, 0x5CB00004, 0x00028053, 0xD1084401, 0x0E014844, 0x21500148,
   0x05090043, 0x4030D011, 0x47AB34C8, 0x917AD1CC, 0x88A7AB18, 0x814D7AD1, 0xC26C778F, 0x2C80C678,
   0xF3084C77, 0xAB1825CB, 0x7AD38264, 0xC7AB1C25, 0xC67AD348, 0x0C67CE00, 0x23CE78D3, 0x826CD7F6,
   0x2084C77A, 0xD1884C77, 0xCE006700, 0x72001E3C, 0x720135FA, 0x902232DE, 0xB4D0991D, 0xC8007CE2,
   0x0234D000, 0x05108680, 0x85201BD5, 0x0005EDCC, 0x32041EB4, 0x632041CC, 0x00720025, 0x1BC7D004,
   0xC8007D02, 0x46308000, 0x04000280, 0x53D10844, 0x010E0148, 0x4030DC80, 0x07AB18C8, 0x917AD1CC,
   0x0817AB2C, 0x23467EC4, 0x023C6730, 0x01C80094, 0x6F1EAC60, 0x272DEB47, 0x08F1DEAC, 0xB31225EB,
   0x4C12441F, 0x30008F19, 0xE34B08D2, 0xDEDCD221, 0x19EB4622, 0x119E3470, 0x9731C800, 0x7B72C804,
   0x77AD2C80, 0x477CC202, 0x5C600005, 0x108680AF, 0xD4001000, 0x0A014F44, 0x21100438, 0x05211085,
   0x40052014, 0x24010D00, 0xC340451E, 0xAC632245, 0xEB473220, 0x9EACB215, 0x19EB4602, 0x519E3472,
   0x031DE34B, 0x2132DEAC, 0xC2231DEB, 0x4708F1DE, 0x34609919, 0xC8007AB1, 0x823477EC, 0x40264C73,
   0x001C8009, 0x46F1EACC, 0x0992DEB4, 0xB0972DE3, 0x4609919E, 0xAC730441, 0xEB4D3144, 0x1F30008D,
   0x2DC80078, 0xD1C80477, 0x8D2C804D, 0x7AB1823C, 0xC7AD1C88, 0x4B72001F, 0x30808F18, 0x00014421,
   0xA02BF500, 0x04000280, 0x53D10844, 0x010E0142, 0x40449004, 0x37893040, 0x0A7AB2CC, 0x0007AD18,
   0xC1007AB2, 0xC804B7AD, 0x1880467A, 0xB1CC4087, 0xAD34C400, 0x78D2C234, 0xB78D1C26, 0xC778D2C2,
   0x5CC70D39, 0xE3C60971, 0xE0167716, 0x02A03A70, 0xA69E24A0, 0x0069CC00, 0x78F2C254, 0xA4005110,
   0x847EA004, 0x8817EC20, 0x48894010, 0xD01457EA, 0x0048817E, 0xC20089A7, 0xEA08089A, 0x7EC2808C,
   0xB4005001, 0x0074615C, 0x80020004, 0x8120DCEA, 0x673AC80E, 0x11CB8072, 0x000A1002, 0x80010145,
   0x44219F40, 0x13140940, 0x0178D28C, 0x48178F2C, 0xC4817AB3, 0x0254A7AD, 0x3425CB78, 0xD38C5027,
   0x8F1CC502, 0x7AB3825C, 0xE7AD1C23, 0xCA78F282, 0x6CC7EA04, 0x26CC7AD2, 0xC650878D, 0x3423CE78,
   0xF3823CE7, 0xEA0826CD, 0x7AD1C274, 0xE78D3025, 0xCC7EA288, 0x0477EC24, 0x264A0000, 0x500C3405,
   0x14000140, 0x31501430, 0x00040002, 0x71602A03, 0xA70A4DEA, 0x9412211E, 0xB1512231, 0xEAC70285,
   0x1EB4802A, 0x55EACC02, 0x229EB4D0, 0x911DEACE, 0x0224DEB4, 0xC09B31E3, 0xC708F21E, 0x34809939,
   0xCC0078F1, 0xC2447442, 0x12016700, 0x009C580A, 0x80E9C293, 0x7AA50088, 0x87AC4808, 0x8A7AB300,
   0xA147AD2C, 0x08937AB3, 0x4261278F, 0x3025CC78, 0xD3425CD7, 0xAB3826CD, 0x73001EAC, 0xE09B39CC,
   0x007AA542, 0x74E7AA50, 0x26957AA5, 0x026147AC, 0x54274C78, 0x93800137, 0x3001EA94, 0x09C51CC0,
   0x00002102, 0x1440A110, 0x31440E46, 0x011E7200, 0x000087AA, 0x5008947A, 0xA540A157, 0xAB380A95,
   0x73001EAC, 0xE09B39CC, 0x0078D382, 0x64E73001, 0xC800D503, 0x5EA86016, 0x55CC0050, 0x005EA860,
   0x2655CC00, 0x50004000, 0x271602A0, 0x3A70A4DE, 0xAA20224D, 0x10044030, 0xE04DD401, 0x0D109040,
   0x52D11928, 0x12F90043, 0x44241011, 0x64464A04, 0xF94012D1, 0x09040469, 0x1192813E, 0x51004403,
   0x0E04DD40, 0x10D10904, 0x052D1192, 0x812F9004, 0x34424101, 0x1644649F, 0x20010009, 0xF2081002,
   0x9F201100, 0x0DF20910, 0x02D004B4, 0x42410143, 0x4464A04A, 0x04012D10, 0x90404791, 0x192813E5,
   0x004B4424, 0x1F380044, 0x89F20800, 0x089F2010, 0x0089F389, 0x04489004, 0xB4424101, 0x124464A0,
   0x4F94012D, 0x10900040, 0x1D185720, 0x00800120, 0x481014B4, 0x464A04BE, 0x812F9090, 0x04464A04,
   0xA072E01C, 0x80028400, 0xA0004012, 0xD1086814, 0x18000150, 0x00400027, 0x1602A03A, 0x70A4DEAA,
   0x20224D02, 0x0240A110, 0x30A8105D, 0x020640A1, 0x5030C810, 0x5D020840, 0xA31030E8, 0x1239000A,
   0x40239011, 0x480145CC, 0x00720035, 0x11544021, 0x10894045, 0x20051730, 0x01C800D4, 0x45540014,
   0x401500CB, 0x81375004, 0xB4032E04, 0xE8440110, 0x0C381375, 0x00434424, 0x1014B446, 0x4A04A040,
   0x10D10868, 0x14180001, 0x78D1CC00, 0x878F20C0, 0x087AB1C8, 0x1477AD20, 0x85487AB2, 0x4C5897AD,
   0x28C1817C, 0xC2424477, 0x8F1C2447, 0x78F2024C, 0xA78D2424, 0xCA7EA002, 0x4477EC20, 0x64897EA0,
   0x424C87EC, 0x24638973, 0x00000017, 0x8D1CC008, 0x78F20C00, 0x87AB2823, 0xC77AD242, 0x4477AB1C,
   0xC4817AD2, 0x0C08178D, 0x1C23C778, 0xD2024487, 0x3001E3C8, 0x09321E3C, 0xA08F29FA, 0x820911DF,
   0xB0309321, 0xFA8A0952, 0x5FB0B095, 0x1DCC0000, 0x005FA811, 0x2201FB09, 0x12221111, 0x17C80800,
   0x227EA28C, 0x48173000, 0x000178D1, 0xCC0087CE, 0x24C00878, 0xF2023C77, 0xCC042447, 0x44041109,
   0x17CC04C0, 0x0073001F, 0xA8910221, 0xCC000000, 0x5FA8B102, 0x25CC0000, 0x021F3023, 0x0021F38A,
   0x30021F30, 0x330205CC, 0x00000200, 0x00144441, 0xF20A0008, 0x9E414304, 0x29FA8112, 0x801FB091,
   0x2821CC00, 0x00004000, 0x28053D02, 0x0240A1D0, 0x30E805C5, 0xC8000200, 0x0C001716, 0x01C09271,
   0x44CC0924, 0x0039009A, 0x40429039, 0x38017DCC, 0x00944550, 0x21A40A1D, 0x030D8026, 0xDCC00400,
   0x19008A40, 0x42D03938, 0x017DCC00, 0x00021000, 0xC4022D01, 0x0B80119C, 0xC0000021, 0x000D4022,
   0xD010B801, 0x7DCC0094, 0x454C0003, 0x02414001, 0x00008080, 0x070A68C0, 0x0171601C, 0x0927144C,
   0xC0924086, 0x9028B40C, 0x36009B73, 0x001000C4, 0x0235011C, 0x40E4E005, 0xF7300100, 0x0A402350,
   0x11B8017D, 0xCC000300, 0x0C000302, 0x42014F40, 0x821029B4, 0x0C7A0171, 0x72001020, 0x240A7103,
   0x1C805C5C, 0x80040271, 0x00438052, 0x1009E400, 0x52014240, 0x10D00C34, 0x04536292, 0x98C15008,
   0xED885262, 0xBF720000, 0x80030005, 0xC5807024, 0x9C513302, 0x49000E40, 0x269011C4, 0x0E4E005F,
   0x73000000, 0x84007100, 0x8A4046E0, 0x05173001, 0xC800D445, 0x4C000302, 0x41400100, 0x00808008,
   0x078A01D6, 0x40009008, 0x04046E01, 0xC8030010, 0x0824010E, 0x0142D88B, 0x26340500, 0x05400100,
   0x00400015, 0x00054001
};


/**
 * @brief Initialize BA414E public key accelerator
 * @return Error code
 **/

error_t ba414eInit(void)
{
   uint_t i;
   uint_t j;
   const uint32_t *src;
   volatile uint32_t *dest;

   //Point to the microcode to be loaded
   src = ucode;
   //Point to the microcode SRAM
   dest = KVA0_TO_KVA1(__CRYPTO1UCM_BASE);

   //Initialize the microcode RAM with the microcode
   for(i = 0; i < arraysize(ucode) / 9; i++)
   {
      //Load the current block
      dest[0] = src[0] >> 14;
      dest[1] = src[0] << 4;
      dest[1] |= src[1] >> 28;
      dest[2] = src[1] >> 10;
      dest[3] = src[1] << 8;
      dest[3] |= src[2] >> 24;
      dest[4] = src[2] >> 6;
      dest[5] = src[2] << 12;
      dest[5] |= src[3] >> 20;
      dest[6] = src[3] >> 2;
      dest[7] = src[3] << 16;
      dest[7] |= src[4] >> 16;
      dest[8] = src[4] << 2;
      dest[8] |= src[5] >> 30;
      dest[9] = src[5] >> 12;
      dest[10] = src[5] << 6;
      dest[10] |= src[6] >> 26;
      dest[11] = src[6] >> 8;
      dest[12] = src[6] << 10;
      dest[12] |= src[7] >> 22;
      dest[13] = src[7] >> 4;
      dest[14] = src[7] << 14;
      dest[14] |= src[8] >> 18;
      dest[15] = src[8];

      //Each block contains 16 words of 18 bits
      for(j = 0; j < 16; j++)
      {
         dest[j] &= 0x3FFFF;
      }

      //Point to the next block
      src += 9;
      dest += 16;
   }

   //Clear the SCM memory
   ba414eClearScm();

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Clear SCM memory
 **/

void ba414eClearScm(void)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the SCM memory
   p = (uint32_t *) __CRYPTO1SCM_BASE;

   //The SCM memory contains 304 words of 64 bits
   for(i = 0; i < 608; i++)
   {
      p[i] = 0;
   }
}


/**
 * @brief Import byte array
 * @param[in] src Pointer to the byte array
 * @param[in] length Length of the array to be copied, in bytes
 * @param[in] slot SCM memory location
 **/

void ba414eImportArray(const uint8_t *src, size_t length, uint_t slot)
{
   uint_t i;
   uint_t j;
   uint32_t temp;
   volatile uint32_t *p;

   //Point to the specified SCM memory location
   p = BA414E_GET_SCM_SLOT(slot);

   //Copy the array to the SCM memory
   for(i = 0, j = 0; i < length; i++)
   {
      switch(i % 4)
      {
      case 0:
         temp = src[length - i - 1];
         break;
      case 1:
         temp |= src[length - i - 1] << 8;
         break;
      case 2:
         temp |= src[length - i - 1] << 16;
         break;
      default:
         temp |= src[length - i - 1] << 24;
         p[j++] = temp;
         break;
      }
   }

   //Pad the operand with zeroes
   for(; i < 64; i++)
   {
      switch(i % 4)
      {
      case 0:
         temp = 0;
         break;
      case 3:
         p[j++] = temp;
         break;
      default:
         break;
      }
   }
}


/**
 * @brief Import scalar
 * @param[in] src Pointer to the scalar
 * @param[in] length Length of the scalar, in words
 * @param[in] slot SCM memory location
 **/

void ba414eImportScalar(const uint32_t *src, uint_t length, uint_t slot)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified SCM memory location
   p = BA414E_GET_SCM_SLOT(slot);

   //Copy the scalar to the SCM memory
   for(i = 0; i < length; i++)
   {
      p[i] = src[i];
   }

   //Pad the operand with zeroes
   for(; i < 16; i++)
   {
      p[i] = 0;
   }
}


/**
 * @brief Import multiple-precision integer
 * @param[in] src Pointer to the multiple-precision integer
 * @param[in] size Size of the operand, in words
 * @param[in] slot SCM memory location
 **/

void ba414eImportMpi(const Mpi *src, uint_t slot)
{
   uint_t i;
   uint_t length;
   volatile uint32_t *p;

   //Get the actual length of the multiple-precision integer, in words
   length = mpiGetLength(src);

   //Point to the specified SCM memory location
   p = BA414E_GET_SCM_SLOT(slot);

   //Copy the multiple-precision integer to the SCM memory
   for(i = 0; i < length && i < 16; i++)
   {
      p[i] = src->data[i];
   }

   //Pad the operand with zeroes
   for(; i < 16; i++)
   {
      p[i] = 0;
   }
}


/**
 * @brief Export scalar
 * @param[out] dest Pointer to the scalar
 * @param[in] length Length of the scalar, in words
 * @param[in] slot SCM memory location
 * @return Error code
 **/

void ba414eExportScalar(uint32_t *dest, uint_t length, uint_t slot)
{
   uint_t i;
   volatile uint32_t *p;

   //Point to the specified SCM memory location
   p = BA414E_GET_SCM_SLOT(slot);

   //Copy the scalar from the SCM memory
   for(i = 0; i < length; i++)
   {
      dest[i] = p[i];
   }
}


/**
 * @brief Export multiple-precision integer
 * @param[out] dest Pointer to the multiple-precision integer
 * @param[in] slot SCM memory location
 * @return Error code
 **/

error_t ba414eExportMpi(Mpi *dest, uint_t slot)
{
   error_t error;
   uint_t i;
   uint_t length;
   volatile uint32_t *p;

   //Point to the specified SCM memory location
   p = BA414E_GET_SCM_SLOT(slot);

   //Skip trailing zeroes
   for(length = 16; length > 0 && p[length - 1] == 0; length--)
   {
   }

   //Ajust the size of the multiple precision integer
   error = mpiGrow(dest, length);

   //Check status code
   if(!error)
   {
      //Copy the multiple-precision integer from the SCM memory
      for(i = 0; i < length; i++)
      {
         dest->data[i] = p[i];
      }

      //Pad the resulting value with zeroes
      for(; i < dest->size; i++)
      {
         dest->data[i] = 0;
      }

      //Set the sign
      dest->sign = 1;
   }

   //Return status code
   return error;
}


#if (MPI_SUPPORT == ENABLED)

/**
 * @brief Modular exponentiation (regular calculation)
 * @param[out] r Resulting integer R = A ^ E mod P
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] e Exponent
 * @param[in] p Modulus
 * @return Error code
 **/

error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   uint_t aLen;
   uint_t eLen;
   uint_t pLen;
   uint_t opSize;

   //Get the length of the integer, in words
   aLen = mpiGetLength(a);
   //Get the length of the exponent, in words
   eLen = mpiGetLength(e);
   //Get the length of the modulus, in words
   pLen = mpiGetLength(p);

   //The accelerator supports operand lengths up to 512 bits
   if(mpiIsOdd(p) && pLen <= 16 && aLen <= pLen && eLen <= pLen)
   {
      //Acquire exclusive access to the BA414E module
      osAcquireMutex(&pic32mzCryptoMutex);

      //Determine the size of the operands
      if(pLen <= 4)
      {
         opSize = PKCOMMAND_OPSIZE_128B;
      }
      else if(pLen <= 8)
      {
         opSize = PKCOMMAND_OPSIZE_256B;
      }
      else
      {
         opSize = PKCOMMAND_OPSIZE_512B;
      }

      //Clear the SCM memory
      ba414eClearScm();

      //Write all required parameters, operands and data into the SCM memory
      ba414eImportMpi(p, BA414E_RSA_MOD_EXP_SLOT_P);
      ba414eImportMpi(a, BA414E_RSA_MOD_EXP_SLOT_A);
      ba414eImportMpi(e, BA414E_RSA_MOD_EXP_SLOT_E);

      //Specify locations where operands are stored in the SCM memory
      PKCONFIG = (BA414E_RSA_MOD_EXP_SLOT_A << _PKCONFIG_OPPTRA_POSITION) |
         (BA414E_RSA_MOD_EXP_SLOT_E << _PKCONFIG_OPPTRB_POSITION) |
         (BA414E_RSA_MOD_EXP_SLOT_C << _PKCONFIG_OPPTRC_POSITION);

      //Specify the operation to be performed
      PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OP_RSA_MOD_EXP | opSize;

      //Set the START signal in the control register
      PKCONTROL = _PKCONTROL_START_MASK;

      //The START signal is automatically cleared when the operation is finished
      while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
      {
      }

      //Read the result from the SCM memory
      error = ba414eExportMpi(r, BA414E_RSA_MOD_EXP_SLOT_C);

      //Release exclusive access to the BA414E module
      osReleaseMutex(&pic32mzCryptoMutex);
   }
   else
   {
      //Perform modular exponentiation
      error = mpiExpMod(r, a, e, p);
   }

   //Return status code
   return error;
}

#endif
#if (EC_SUPPORT == ENABLED)

/**
 * @brief Scalar multiplication (fast calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulFast(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   //Compute R = d.S
   return ecMulRegular(curve, r, d, s);
}


/**
 * @brief Scalar multiplication (regular calculation)
 * @param[in] curve Elliptic curve parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < q
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMulRegular(const EcCurve *curve, EcPoint3 *r, const uint32_t *d,
   const EcPoint3 *s)
{
   error_t error;
   uint_t modLen;
   uint_t orderLen;
   uint_t opSize;

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //The accelerator supports operand lengths up to 512 bits
   if(modLen <= 4 && orderLen <= 4)
   {
      opSize = PKCOMMAND_OPSIZE_128B;
   }
   else if(modLen <= 8 && orderLen <= 8)
   {
      opSize = PKCOMMAND_OPSIZE_256B;
   }
   else if(modLen <= 16 && orderLen <= 16)
   {
      opSize = PKCOMMAND_OPSIZE_512B;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the BA414E module
   osAcquireMutex(&pic32mzCryptoMutex);

   //Clear the SCM memory
   ba414eClearScm();

   //Write all required parameters, operands and data into the SCM memory
   ba414eImportScalar(curve->p, modLen, BA414E_ECC_SLOT_P);
   ba414eImportScalar(curve->q, orderLen, BA414E_ECC_SLOT_N);
   ba414eImportScalar(curve->g.x, modLen, BA414E_ECC_SLOT_GX);
   ba414eImportScalar(curve->g.y, modLen, BA414E_ECC_SLOT_GY);
   ba414eImportScalar(curve->a, modLen, BA414E_ECC_SLOT_A);
   ba414eImportScalar(curve->b, modLen, BA414E_ECC_SLOT_B);
   ba414eImportScalar(s->x, modLen, BA414E_ECC_SLOT_P1X);
   ba414eImportScalar(s->y, modLen, BA414E_ECC_SLOT_P1Y);
   ba414eImportScalar(d, orderLen, BA414E_ECC_SLOT_K);

   //Specify locations where operands are stored in the SCM memory
   PKCONFIG = (BA414E_ECC_SLOT_P1X << _PKCONFIG_OPPTRA_POSITION) |
      (BA414E_ECC_SLOT_K << _PKCONFIG_OPPTRB_POSITION) |
      (BA414E_ECC_SLOT_P3X << _PKCONFIG_OPPTRC_POSITION);

   //Specify the operation to be performed
   PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OP_ECC_POINT_MUL | opSize;

   //Set the START signal in the control register
   PKCONTROL = _PKCONTROL_START_MASK;

   //The START signal is automatically cleared when the operation is finished
   while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
   {
   }

   //Point at the infinity?
   if((PKSTATUS & _PKSTATUS_PXINF_MASK) != 0)
   {
      //Set R = (1, 1, 0)
      ecScalarSetInt(r->x, 1, EC_MAX_MODULUS_SIZE);
      ecScalarSetInt(r->y, 1, EC_MAX_MODULUS_SIZE);
      ecScalarSetInt(r->z, 0, EC_MAX_MODULUS_SIZE);
   }
   else
   {
      //Copy the x-coordinate of the result
      ecScalarSetInt(r->x, 0, EC_MAX_MODULUS_SIZE);
      ba414eExportScalar(r->x, modLen, BA414E_ECC_SLOT_P3X);

      //Copy the y-coordinate of the result
      ecScalarSetInt(r->y, 0, EC_MAX_MODULUS_SIZE);
      ba414eExportScalar(r->y, modLen, BA414E_ECC_SLOT_P3Y);

      //Set the z-coordinate of the result
      ecScalarSetInt(r->z, 1, EC_MAX_MODULUS_SIZE);
   }

   //Release exclusive access to the BA414E module
   osReleaseMutex(&pic32mzCryptoMutex);

   //Successful processing
   return NO_ERROR;
}

#endif
#if (ECDSA_SUPPORT == ENABLED)

/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcPrivateKey *privateKey, const uint8_t *digest, size_t digestLen,
   EcdsaSignature *signature)
{
   error_t error;
   uint_t modLen;
   uint_t orderLen;
   uint_t opSize;
   uint32_t k[EC_MAX_ORDER_SIZE];
   const EcCurve *curve;

   //Check parameters
   if(privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(privateKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Get elliptic curve parameters
   curve = privateKey->curve;

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //The accelerator supports operand lengths up to 512 bits
   if(modLen <= 4 && orderLen <= 4)
   {
      opSize = PKCOMMAND_OPSIZE_128B;
   }
   else if(modLen <= 8 && orderLen <= 8)
   {
      opSize = PKCOMMAND_OPSIZE_256B;
   }
   else if(modLen <= 16 && orderLen <= 16)
   {
      opSize = PKCOMMAND_OPSIZE_512B;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Generate a random number k such as 0 < k < q - 1
   error = ecScalarRand(curve, k, prngAlgo, prngContext);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the BA414E module
      osAcquireMutex(&pic32mzCryptoMutex);

      //Clear the SCM memory
      ba414eClearScm();

      //Write all required parameters, operands and data into the SCM memory
      ba414eImportScalar(curve->p, modLen, BA414E_ECDSA_SLOT_P);
      ba414eImportScalar(curve->q, orderLen, BA414E_ECDSA_SLOT_N);
      ba414eImportScalar(curve->g.x, modLen, BA414E_ECDSA_SLOT_GX);
      ba414eImportScalar(curve->g.y, modLen, BA414E_ECDSA_SLOT_GY);
      ba414eImportScalar(curve->a, modLen, BA414E_ECDSA_SLOT_A);
      ba414eImportScalar(curve->b, modLen, BA414E_ECDSA_SLOT_B);
      ba414eImportScalar(privateKey->d, orderLen, BA414E_ECDSA_SLOT_D);
      ba414eImportScalar(k, orderLen, BA414E_ECDSA_SLOT_K);

      //Keep the leftmost bits of the hash value
      digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);
      //Load the hash value into the SCM memory
      ba414eImportArray(digest, digestLen, BA414E_ECDSA_SLOT_H);

      //Clear PKCONFIG register
      PKCONFIG = 0;
      //Specify the operation to be performed
      PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OP_ECDSA_SIGN_GEN | opSize;
      //Set the START signal in the control register
      PKCONTROL = _PKCONTROL_START_MASK;

      //The START signal is automatically cleared when the operation is finished
      while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
      {
      }

      //Check status register
      if((PKSTATUS & (_PKSTATUS_SIGINVAL_MASK | _PKSTATUS_CPLINVAL_MASK |
         _PKSTATUS_PXINF_MASK | _PKSTATUS_PXNOC_MASK)) == 0)
      {
         //Save elliptic curve parameters
         signature->curve = curve;

         //Copy integer R
         ecScalarSetInt(signature->r, 0, EC_MAX_ORDER_SIZE);
         ba414eExportScalar(signature->r, orderLen, BA414E_ECDSA_SLOT_R);

         //Copy integer S
         ecScalarSetInt(signature->s, 0, EC_MAX_ORDER_SIZE);
         ba414eExportScalar(signature->s, orderLen, BA414E_ECDSA_SLOT_S);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the BA414E module
      osReleaseMutex(&pic32mzCryptoMutex);
   }

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcPublicKey *publicKey,
   const uint8_t *digest, size_t digestLen, const EcdsaSignature *signature)
{
   error_t error;
   uint_t modLen;
   uint_t orderLen;
   uint_t opSize;
   const EcCurve *curve;

   //Check parameters
   if(publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid elliptic curve?
   if(publicKey->curve == NULL)
      return ERROR_INVALID_ELLIPTIC_CURVE;

   //Verify that the public key is on the curve
   if(!ecIsPointAffine(publicKey->curve, &publicKey->q))
   {
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < r < q
   if(ecScalarCompInt(signature->r, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->r, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(ecScalarCompInt(signature->s, 0, EC_MAX_ORDER_SIZE) <= 0 ||
      ecScalarComp(signature->s, publicKey->curve->q, EC_MAX_ORDER_SIZE) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //Get elliptic curve parameters
   curve = publicKey->curve;

   //Get the length of the modulus, in words
   modLen = (curve->fieldSize + 31) / 32;
   //Get the length of the order, in words
   orderLen = (curve->orderSize + 31) / 32;

   //The accelerator supports operand lengths up to 512 bits
   if(modLen <= 4 && orderLen <= 4)
   {
      opSize = PKCOMMAND_OPSIZE_128B;
   }
   else if(modLen <= 8 && orderLen <= 8)
   {
      opSize = PKCOMMAND_OPSIZE_256B;
   }
   else if(modLen <= 16 && orderLen <= 16)
   {
      opSize = PKCOMMAND_OPSIZE_512B;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the BA414E module
   osAcquireMutex(&pic32mzCryptoMutex);

   //Clear the SCM memory
   ba414eClearScm();

   //Write all required parameters, operands and data into the SCM memory
   ba414eImportScalar(curve->p, modLen, BA414E_ECDSA_SLOT_P);
   ba414eImportScalar(curve->q, orderLen, BA414E_ECDSA_SLOT_N);
   ba414eImportScalar(curve->g.x, modLen, BA414E_ECDSA_SLOT_GX);
   ba414eImportScalar(curve->g.y, modLen, BA414E_ECDSA_SLOT_GY);
   ba414eImportScalar(curve->a, modLen, BA414E_ECDSA_SLOT_A);
   ba414eImportScalar(curve->b, modLen, BA414E_ECDSA_SLOT_B);
   ba414eImportScalar(publicKey->q.x, modLen, BA414E_ECDSA_SLOT_QX);
   ba414eImportScalar(publicKey->q.y, modLen, BA414E_ECDSA_SLOT_QY);
   ba414eImportScalar(signature->r, orderLen, BA414E_ECDSA_SLOT_R);
   ba414eImportScalar(signature->s, orderLen, BA414E_ECDSA_SLOT_S);

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, (curve->orderSize + 7) / 8);
   //Load the hash value into the SCM memory
   ba414eImportArray(digest, digestLen, BA414E_ECDSA_SLOT_H);

   //Clear PKCONFIG register
   PKCONFIG = 0;
   //Specify the operation to be performed
   PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OP_ECDSA_SIGN_VERIFY | opSize;
   //Set the START signal in the control register
   PKCONTROL = _PKCONTROL_START_MASK;

   //The START signal is automatically cleared when the operation is finished
   while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
   {
   }

   //Check status register
   if((PKSTATUS & (_PKSTATUS_SIGINVAL_MASK | _PKSTATUS_CPLINVAL_MASK |
      _PKSTATUS_PXINF_MASK | _PKSTATUS_PXNOC_MASK)) == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_INVALID_SIGNATURE;
   }

   //Release exclusive access to the BA414E module
   osReleaseMutex(&pic32mzCryptoMutex);

   //Return status code
   return error;
}

#endif
#if (X25519_SUPPORT == ENABLED)

/**
 * @brief X25519 function (scalar multiplication on Curve25519)
 * @param[out] r Output u-coordinate
 * @param[in] k Input scalar
 * @param[in] u Input u-coordinate
 * @return Error code
 **/

error_t x25519(uint8_t *r, const uint8_t *k, const uint8_t *u)
{
   volatile uint32_t *arg;

   //Acquire exclusive access to the BA414E module
   osAcquireMutex(&pic32mzCryptoMutex);

   //Clear the SCM memory
   ba414eClearScm();

   //Write the modulus into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_CURVE25519_SLOT_P);
   arg[0] = 0xFFFFFFED;
   arg[1] = 0xFFFFFFFF;
   arg[2] = 0xFFFFFFFF;
   arg[3] = 0xFFFFFFFF;
   arg[4] = 0xFFFFFFFF;
   arg[5] = 0xFFFFFFFF;
   arg[6] = 0xFFFFFFFF;
   arg[7] = 0x7FFFFFFF;

   //Write the input u-coordinate into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_CURVE25519_SLOT_X1);
   arg[0] = LOAD32LE(u);
   arg[1] = LOAD32LE(u + 4);
   arg[2] = LOAD32LE(u + 8);
   arg[3] = LOAD32LE(u + 12);
   arg[4] = LOAD32LE(u + 16);
   arg[5] = LOAD32LE(u + 20);
   arg[6] = LOAD32LE(u + 24);
   arg[7] = LOAD32LE(u + 28);

   //Implementations must mask the most significant bit in the final byte
   arg[7] &= 0x7FFFFFFF;

   //Write the pre-calculated value of (a - 2) / 4) into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_CURVE25519_SLOT_A24);
   arg[0] = 121665;
   arg[1] = 0;
   arg[2] = 0;
   arg[3] = 0;
   arg[4] = 0;
   arg[5] = 0;
   arg[6] = 0;
   arg[7] = 0;

   //Write the scalar into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_CURVE25519_SLOT_K);
   arg[0] = LOAD32LE(k);
   arg[1] = LOAD32LE(k + 4);
   arg[2] = LOAD32LE(k + 8);
   arg[3] = LOAD32LE(k + 12);
   arg[4] = LOAD32LE(k + 16);
   arg[5] = LOAD32LE(k + 20);
   arg[6] = LOAD32LE(k + 24);
   arg[7] = LOAD32LE(k + 28);

   //Set the three least significant bits of the first byte and the most
   //significant bit of the last to zero, set the second most significant
   //bit of the last byte to 1
   arg[0] &= 0xFFFFFFF8;
   arg[7] &= 0x7FFFFFFF;
   arg[7] |= 0x40000000;

   //Specify locations where operands are stored in the SCM memory
   PKCONFIG = (BA414E_CURVE25519_SLOT_X1 << _PKCONFIG_OPPTRA_POSITION) |
      (BA414E_CURVE25519_SLOT_K << _PKCONFIG_OPPTRB_POSITION) |
      (BA414E_CURVE25519_SLOT_X3 << _PKCONFIG_OPPTRC_POSITION);

   //Specify the operation to be performed
   PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OPSIZE_256B |
      PKCOMMAND_OP_CURVE25519_POINT_MUL;

   //Set the START signal in the control register
   PKCONTROL = _PKCONTROL_START_MASK;

   //The START signal is automatically cleared when the operation is finished
   while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
   {
   }

   //Read the result from the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_CURVE25519_SLOT_X3);
   STORE32LE(arg[0], r);
   STORE32LE(arg[1], r + 4);
   STORE32LE(arg[2], r + 8);
   STORE32LE(arg[3], r + 12);
   STORE32LE(arg[4], r + 16);
   STORE32LE(arg[5], r + 20);
   STORE32LE(arg[6], r + 24);
   STORE32LE(arg[7], r + 28);

   //Release exclusive access to the BA414E module
   osReleaseMutex(&pic32mzCryptoMutex);

   //Successful processing
   return NO_ERROR;
}

#endif
#if (ED25519_SUPPORT == ENABLED)

/**
 * @brief Scalar multiplication (regular calculation)
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = k * P
 * @param[in] k Input scalar
 * @param[in] p Input point
 **/

void ed25519Mul(Ed25519SubState *state, Ed25519Point *r,
   const uint8_t *k, const Ed25519Point *p)
{
   volatile uint32_t *arg;

   //Acquire exclusive access to the BA414E module
   osAcquireMutex(&pic32mzCryptoMutex);

   //Clear the SCM memory
   ba414eClearScm();

   //Write the modulus into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_P);
   arg[0] = 0xFFFFFFED;
   arg[1] = 0xFFFFFFFF;
   arg[2] = 0xFFFFFFFF;
   arg[3] = 0xFFFFFFFF;
   arg[4] = 0xFFFFFFFF;
   arg[5] = 0xFFFFFFFF;
   arg[6] = 0xFFFFFFFF;
   arg[7] = 0x7FFFFFFF;

   //Write the pre-calculated value of D2 into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_D2);
   arg[0] = 0xBE8FD3F4;
   arg[1] = 0x01DB17FD;
   arg[2] = 0x5F8C52E7;
   arg[3] = 0x21430EEF;
   arg[4] = 0x78310D20;
   arg[5] = 0xCB27240F;
   arg[6] = 0xE53F8A4D;
   arg[7] = 0x590456B4;

   //Write the x-coordinate of the input point into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_PX);
   arg[0] = (p->x[1] << 29) | p->x[0];
   arg[1] = (p->x[2] << 26) | (p->x[1] >> 3);
   arg[2] = (p->x[3] << 23) | (p->x[2] >> 6);
   arg[3] = (p->x[4] << 20) | (p->x[3] >> 9);
   arg[4] = (p->x[5] << 17) | (p->x[4] >> 12);
   arg[5] = (p->x[6] << 14) | (p->x[5] >> 15);
   arg[6] = (p->x[7] << 11) | (p->x[6] >> 18);
   arg[7] = (p->x[8] << 8) | (p->x[7] >> 21);

   //Write the y-coordinate of the input point into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_PY);
   arg[0] = (p->y[1] << 29) | p->y[0];
   arg[1] = (p->y[2] << 26) | (p->y[1] >> 3);
   arg[2] = (p->y[3] << 23) | (p->y[2] >> 6);
   arg[3] = (p->y[4] << 20) | (p->y[3] >> 9);
   arg[4] = (p->y[5] << 17) | (p->y[4] >> 12);
   arg[5] = (p->y[6] << 14) | (p->y[5] >> 15);
   arg[6] = (p->y[7] << 11) | (p->y[6] >> 18);
   arg[7] = (p->y[8] << 8) | (p->y[7] >> 21);

   //Write the scalar into the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_E);
   arg[0] = LOAD32LE(k);
   arg[1] = LOAD32LE(k + 4);
   arg[2] = LOAD32LE(k + 8);
   arg[3] = LOAD32LE(k + 12);
   arg[4] = LOAD32LE(k + 16);
   arg[5] = LOAD32LE(k + 20);
   arg[6] = LOAD32LE(k + 24);
   arg[7] = LOAD32LE(k + 28);

   //Specify locations where operands are stored in the SCM memory
   PKCONFIG = (BA414E_ED25519_SLOT_PX << _PKCONFIG_OPPTRA_POSITION) |
      (BA414E_ED25519_SLOT_E << _PKCONFIG_OPPTRB_POSITION) |
      (BA414E_ED25519_SLOT_CX << _PKCONFIG_OPPTRC_POSITION);

   //Specify the operation to be performed
   PKCOMMAND = _PKCOMMAND_CALCR2_MASK | PKCOMMAND_OPSIZE_256B |
      PKCOMMAND_OP_ED25519_SCALAR_MUL;

   //Set the START signal in the control register
   PKCONTROL = _PKCONTROL_START_MASK;

   //The START signal is automatically cleared when the operation is finished
   while((PKSTATUS & _PKSTATUS_BUSY_MASK) != 0)
   {
   }

   //Read the x-coordinate of the resulting point from the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_CX);
   r->x[0] = arg[0] & 0x1FFFFFFF;
   r->x[1] = (arg[0] >> 29) | ((arg[1] << 3) & 0x1FFFFFFF);
   r->x[2] = (arg[1] >> 26) | ((arg[2] << 6) & 0x1FFFFFFF);
   r->x[3] = (arg[2] >> 23) | ((arg[3] << 9) & 0x1FFFFFFF);
   r->x[4] = (arg[3] >> 20) | ((arg[4] << 12) & 0x1FFFFFFF);
   r->x[5] = (arg[4] >> 17) | ((arg[5] << 15) & 0x1FFFFFFF);
   r->x[6] = (arg[5] >> 14) | ((arg[6] << 18) & 0x1FFFFFFF);
   r->x[7] = (arg[6] >> 11) | ((arg[7] << 21) & 0x1FFFFFFF);
   r->x[8] = arg[7] >> 8;

   //Read the y-coordinate of the resulting point from the SCM memory
   arg = BA414E_GET_SCM_SLOT(BA414E_ED25519_SLOT_CY);
   r->y[0] = arg[0] & 0x1FFFFFFF;
   r->y[1] = (arg[0] >> 29) | ((arg[1] << 3) & 0x1FFFFFFF);
   r->y[2] = (arg[1] >> 26) | ((arg[2] << 6) & 0x1FFFFFFF);
   r->y[3] = (arg[2] >> 23) | ((arg[3] << 9) & 0x1FFFFFFF);
   r->y[4] = (arg[3] >> 20) | ((arg[4] << 12) & 0x1FFFFFFF);
   r->y[5] = (arg[4] >> 17) | ((arg[5] << 15) & 0x1FFFFFFF);
   r->y[6] = (arg[5] >> 14) | ((arg[6] << 18) & 0x1FFFFFFF);
   r->y[7] = (arg[6] >> 11) | ((arg[7] << 21) & 0x1FFFFFFF);
   r->y[8] = arg[7] >> 8;

   //Release exclusive access to the BA414E module
   osReleaseMutex(&pic32mzCryptoMutex);

   //Calculate extended point representation
   curve25519SetInt(r->z, 1);
   curve25519Mul(r->t, r->x, r->y);
}


/**
 * @brief Twin multiplication
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = k1 * P + k2 * Q
 * @param[in] k1 First input scalar
 * @param[in] p First input point
 * @param[in] k2 Second input scalar
 * @param[in] q Second input point
 **/

void ed25519TwinMul(Ed25519SubState *state, Ed25519Point *r,
   const uint8_t *k1, const Ed25519Point *p, const uint8_t *k2,
   const Ed25519Point *q)
{
   Ed25519Point p1;
   Ed25519Point p2;

   //Reduce non-canonical values
   curve25519Canonicalize(p1.x, p->x);
   curve25519Canonicalize(p1.y, p->y);
   curve25519Canonicalize(p2.x, q->x);
   curve25519Canonicalize(p2.y, q->y);

   //Compute R = k1 * P + k2 * Q
   ed25519Mul(state, &p1, k1, &p1);
   ed25519Mul(state, &p2, k2, &p2);
   ed25519Add(state, r, &p1, &p2);
}

#endif
#endif
